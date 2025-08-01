package dockerfile

// This file contains the dispatchers for each command. Note that
// `nullDispatch` is not actually a command, but support for commands we parse
// but do nothing with.
//
// See evaluator.go for a higher level discussion of the whole evaluator
// package.

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/containerd/platforms"
	"github.com/docker/docker/daemon/builder"
	"github.com/docker/docker/daemon/internal/image"
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/nat"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/sys/signal"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// noBaseImageSpecifier is the symbol used by the FROM
// command to specify that no base image is to be used.
const noBaseImageSpecifier = "scratch"

// ENV foo bar
//
// Sets the environment variable foo to bar, also makes interpolation
// in the dockerfile available from the next statement on via ${foo}.
func dispatchEnv(ctx context.Context, d dispatchRequest, c *instructions.EnvCommand) error {
	runConfig := d.state.runConfig
	commitMessage := bytes.NewBufferString("ENV")
	for _, e := range c.Env {
		name := e.Key
		newVar := e.String()

		commitMessage.WriteString(" " + newVar)
		gotOne := false
		for i, envVar := range runConfig.Env {
			compareFrom, _, _ := strings.Cut(envVar, "=")
			if shell.EqualEnvKeys(compareFrom, name) {
				runConfig.Env[i] = newVar
				gotOne = true
				break
			}
		}
		if !gotOne {
			runConfig.Env = append(runConfig.Env, newVar)
		}
	}
	return d.builder.commit(ctx, d.state, commitMessage.String())
}

// MAINTAINER some text <maybe@an.email.address>
//
// Sets the maintainer metadata.
func dispatchMaintainer(ctx context.Context, d dispatchRequest, c *instructions.MaintainerCommand) error {
	d.state.maintainer = c.Maintainer
	return d.builder.commit(ctx, d.state, "MAINTAINER "+c.Maintainer)
}

// LABEL some json data describing the image
//
// Sets the Label variable foo to bar,
func dispatchLabel(ctx context.Context, d dispatchRequest, c *instructions.LabelCommand) error {
	if d.state.runConfig.Labels == nil {
		d.state.runConfig.Labels = make(map[string]string)
	}
	commitStr := "LABEL"
	for _, v := range c.Labels {
		d.state.runConfig.Labels[v.Key] = v.Value
		commitStr += " " + v.String()
	}
	return d.builder.commit(ctx, d.state, commitStr)
}

// ADD foo /path
//
// Add the file 'foo' to '/path'. Tarball and Remote URL (http, https) handling
// exist here. If you do not wish to have this automatic handling, use COPY.
func dispatchAdd(ctx context.Context, d dispatchRequest, c *instructions.AddCommand) error {
	if c.Chmod != "" {
		return errors.New("the --chmod option requires BuildKit. Refer to https://docs.docker.com/go/buildkit/ to learn how to build images with BuildKit enabled")
	}
	downloader := newRemoteSourceDownloader(d.builder.Output, d.builder.Stdout)
	cpr := copierFromDispatchRequest(d, downloader, nil)
	defer cpr.Cleanup()

	instruction, err := cpr.createCopyInstruction(c.SourcesAndDest, "ADD")
	if err != nil {
		return err
	}
	instruction.chownStr = c.Chown
	instruction.allowLocalDecompression = true

	return d.builder.performCopy(ctx, d, instruction)
}

// COPY foo /path
//
// Same as 'ADD' but without the tar and remote url handling.
func dispatchCopy(ctx context.Context, d dispatchRequest, c *instructions.CopyCommand) error {
	if c.Chmod != "" {
		return errors.New("the --chmod option requires BuildKit. Refer to https://docs.docker.com/go/buildkit/ to learn how to build images with BuildKit enabled")
	}
	var im *imageMount
	var err error
	if c.From != "" {
		im, err = d.getImageMount(ctx, c.From)
		if err != nil {
			return errors.Wrapf(err, "invalid from flag value %s", c.From)
		}
	}
	cpr := copierFromDispatchRequest(d, errOnSourceDownload, im)
	defer cpr.Cleanup()
	instruction, err := cpr.createCopyInstruction(c.SourcesAndDest, "COPY")
	if err != nil {
		return err
	}
	instruction.chownStr = c.Chown
	if c.From != "" && instruction.chownStr == "" {
		instruction.preserveOwnership = true
	}
	return d.builder.performCopy(ctx, d, instruction)
}

func (d *dispatchRequest) getImageMount(ctx context.Context, imageRefOrID string) (*imageMount, error) {
	if imageRefOrID == "" {
		// TODO: this could return the source in the default case as well?
		return nil, nil
	}

	var localOnly bool
	stage, err := d.stages.get(imageRefOrID)
	if err != nil {
		return nil, err
	}
	if stage != nil {
		imageRefOrID = stage.Image
		localOnly = true
	}
	return d.builder.imageSources.Get(ctx, imageRefOrID, localOnly, d.builder.platform)
}

// FROM [--platform=platform] imagename[:tag | @digest] [AS build-stage-name]
func initializeStage(ctx context.Context, d dispatchRequest, cmd *instructions.Stage) error {
	err := d.builder.imageProber.Reset(ctx)
	if err != nil {
		return err
	}

	var platform *ocispec.Platform
	if val := cmd.Platform; val != "" {
		v, err := d.getExpandedString(d.shlex, val)
		if err != nil {
			return errors.Wrapf(err, "failed to process arguments for platform %s", v)
		}

		p, err := platforms.Parse(v)
		if err != nil {
			return errors.Wrapf(errdefs.InvalidParameter(err), "failed to parse platform %s", v)
		}
		platform = &p
	}

	img, err := d.getFromImage(ctx, d.shlex, cmd.BaseName, platform)
	if err != nil {
		return err
	}
	state := d.state
	if err := state.beginStage(cmd.Name, img); err != nil {
		return err
	}
	if len(state.runConfig.OnBuild) > 0 {
		triggers := state.runConfig.OnBuild
		state.runConfig.OnBuild = nil
		return dispatchTriggeredOnBuild(ctx, d, triggers)
	}
	return nil
}

func dispatchTriggeredOnBuild(ctx context.Context, d dispatchRequest, triggers []string) error {
	fmt.Fprintf(d.builder.Stdout, "# Executing %d build trigger", len(triggers))
	if len(triggers) > 1 {
		fmt.Fprint(d.builder.Stdout, "s")
	}
	fmt.Fprintln(d.builder.Stdout)
	for _, trigger := range triggers {
		d.state.updateRunConfig()
		ast, err := parser.Parse(strings.NewReader(trigger))
		if err != nil {
			return err
		}
		if len(ast.AST.Children) != 1 {
			return errors.New("onbuild trigger should be a single expression")
		}
		cmd, err := instructions.ParseCommand(ast.AST.Children[0])
		if err != nil {
			var uiErr *instructions.UnknownInstructionError
			if errors.As(err, &uiErr) {
				buildsFailed.WithValues(metricsUnknownInstructionError).Inc()
			}
			return err
		}
		err = dispatch(ctx, d, cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *dispatchRequest) getExpandedString(shlex *shell.Lex, str string) (string, error) {
	substitutionArgs := []string{}
	for key, value := range d.state.buildArgs.GetAllMeta() {
		substitutionArgs = append(substitutionArgs, key+"="+value)
	}

	name, _, err := shlex.ProcessWord(str, shell.EnvsFromSlice(substitutionArgs))
	if err != nil {
		return "", err
	}
	return name, nil
}

func (d *dispatchRequest) getImageOrStage(ctx context.Context, name string, platform *ocispec.Platform) (builder.Image, error) {
	var localOnly bool
	if im, ok := d.stages.getByName(name); ok {
		name = im.Image
		localOnly = true
	}

	if platform == nil {
		platform = d.builder.platform
	}

	// Windows cannot support a container with no base image.
	if name == noBaseImageSpecifier {
		// Windows supports scratch. What is not supported is running containers from it.
		if runtime.GOOS == "windows" {
			return nil, errors.New("Windows does not support FROM scratch")
		}

		// TODO: scratch should not have an os. It should be nil image.
		imageImage := &image.Image{}
		if platform != nil {
			imageImage.OS = platform.OS
		} else {
			imageImage.OS = runtime.GOOS
		}
		return builder.Image(imageImage), nil
	}
	imgMount, err := d.builder.imageSources.Get(ctx, name, localOnly, platform)
	if err != nil {
		return nil, err
	}
	return imgMount.Image(), nil
}

func (d *dispatchRequest) getFromImage(ctx context.Context, shlex *shell.Lex, basename string, platform *ocispec.Platform) (builder.Image, error) {
	name, err := d.getExpandedString(shlex, basename)
	if err != nil {
		return nil, err
	}
	// Empty string is interpreted to FROM scratch by images.GetImageAndReleasableLayer,
	// so validate expanded result is not empty.
	if name == "" {
		return nil, errors.Errorf("base name (%s) should not be blank", basename)
	}

	return d.getImageOrStage(ctx, name, platform)
}

func dispatchOnbuild(ctx context.Context, d dispatchRequest, c *instructions.OnbuildCommand) error {
	d.state.runConfig.OnBuild = append(d.state.runConfig.OnBuild, c.Expression)
	return d.builder.commit(ctx, d.state, "ONBUILD "+c.Expression)
}

// WORKDIR /tmp
//
// Set the working directory for future RUN/CMD/etc statements.
func dispatchWorkdir(ctx context.Context, d dispatchRequest, c *instructions.WorkdirCommand) error {
	runConfig := d.state.runConfig
	var err error
	runConfig.WorkingDir, err = normalizeWorkdir(d.state.operatingSystem, runConfig.WorkingDir, c.Path)
	if err != nil {
		return err
	}

	// For performance reasons, we explicitly do a create/mkdir now
	// This avoids having an unnecessary expensive mount/unmount calls
	// (on Windows in particular) during each container create.
	// Prior to 1.13, the mkdir was deferred and not executed at this step.
	if d.builder.disableCommit {
		// Don't call back into the daemon if we're going through docker commit --change "WORKDIR /foo".
		// We've already updated the runConfig and that's enough.
		return nil
	}

	comment := "WORKDIR " + runConfig.WorkingDir
	runConfigWithCommentCmd := copyRunConfig(runConfig, withCmdCommentString(comment, d.state.operatingSystem))

	containerID, err := d.builder.probeAndCreate(ctx, d.state, runConfigWithCommentCmd)
	if err != nil || containerID == "" {
		return err
	}

	if err := d.builder.docker.ContainerCreateWorkdir(containerID); err != nil {
		return err
	}

	return d.builder.commitContainer(ctx, d.state, containerID, runConfigWithCommentCmd)
}

// RUN some command yo
//
// run a command and commit the image. Args are automatically prepended with
// the current SHELL which defaults to 'sh -c' under linux or 'cmd /S /C' under
// Windows, in the event there is only one argument The difference in processing:
//
// RUN echo hi          # sh -c echo hi       (Linux and LCOW)
// RUN echo hi          # cmd /S /C echo hi   (Windows)
// RUN [ "echo", "hi" ] # echo hi
func dispatchRun(ctx context.Context, d dispatchRequest, c *instructions.RunCommand) error {
	if err := image.CheckOS(d.state.operatingSystem); err != nil {
		return err
	}

	if len(c.FlagsUsed) > 0 {
		// classic builder RUN currently does not support any flags, so fail on the first one
		return errors.Errorf("the --%s option requires BuildKit. Refer to https://docs.docker.com/go/buildkit/ to learn how to build images with BuildKit enabled", c.FlagsUsed[0])
	}

	stateRunConfig := d.state.runConfig
	cmdFromArgs, argsEscaped := resolveCmdLine(c.ShellDependantCmdLine, stateRunConfig, d.state.operatingSystem, c.Name(), c.String())
	buildArgs := d.state.buildArgs.FilterAllowed(stateRunConfig.Env)

	saveCmd := cmdFromArgs
	if len(buildArgs) > 0 {
		saveCmd = prependEnvOnCmd(d.state.buildArgs, buildArgs, cmdFromArgs)
	}

	cacheArgsEscaped := argsEscaped
	// ArgsEscaped is not persisted in the committed image on Windows.
	// Use the original from previous build steps for cache probing.
	if d.state.operatingSystem == "windows" {
		cacheArgsEscaped = stateRunConfig.ArgsEscaped
	}

	runConfigForCacheProbe := copyRunConfig(stateRunConfig,
		withCmd(saveCmd),
		withArgsEscaped(cacheArgsEscaped),
		withEntrypointOverride(saveCmd, nil))
	if hit, err := d.builder.probeCache(d.state, runConfigForCacheProbe); err != nil || hit {
		return err
	}

	runConfig := copyRunConfig(stateRunConfig,
		withCmd(cmdFromArgs),
		withArgsEscaped(argsEscaped),
		withEnv(append(stateRunConfig.Env, buildArgs...)),
		withEntrypointOverride(saveCmd, []string{""}),
		withoutHealthcheck())

	cID, err := d.builder.create(ctx, runConfig)
	if err != nil {
		return err
	}

	if err := d.builder.containerManager.Run(ctx, cID, d.builder.Stdout, d.builder.Stderr); err != nil {
		if err, ok := err.(*statusCodeError); ok {
			// TODO: change error type, because jsonmessage.JSONError assumes HTTP
			msg := fmt.Sprintf(
				"The command '%s' returned a non-zero code: %d",
				strings.Join(runConfig.Cmd, " "), err.StatusCode())
			if err.Error() != "" {
				msg = fmt.Sprintf("%s: %s", msg, err.Error())
			}
			return &jsonstream.Error{
				Message: msg,
				Code:    err.StatusCode(),
			}
		}
		return err
	}

	// Don't persist the argsEscaped value in the committed image. Use the original
	// from previous build steps (only CMD and ENTRYPOINT persist this).
	if d.state.operatingSystem == "windows" {
		runConfigForCacheProbe.ArgsEscaped = stateRunConfig.ArgsEscaped
	}

	return d.builder.commitContainer(ctx, d.state, cID, runConfigForCacheProbe)
}

// Derive the command to use for probeCache() and to commit in this container.
// Note that we only do this if there are any build-time env vars.  Also, we
// use the special argument "|#" at the start of the args array. This will
// avoid conflicts with any RUN command since commands can not
// start with | (vertical bar). The "#" (number of build envs) is there to
// help ensure proper cache matches. We don't want a RUN command
// that starts with "foo=abc" to be considered part of a build-time env var.
//
// remove any unreferenced built-in args from the environment variables.
// These args are transparent so resulting image should be the same regardless
// of the value.
func prependEnvOnCmd(buildArgs *BuildArgs, buildArgVars []string, cmd []string) []string {
	tmpBuildEnv := make([]string, 0, len(buildArgVars))
	for _, env := range buildArgVars {
		key, _, _ := strings.Cut(env, "=")
		if buildArgs.IsReferencedOrNotBuiltin(key) {
			tmpBuildEnv = append(tmpBuildEnv, env)
		}
	}

	sort.Strings(tmpBuildEnv)
	tmpEnv := append([]string{fmt.Sprintf("|%d", len(tmpBuildEnv))}, tmpBuildEnv...)
	return append(tmpEnv, cmd...)
}

// CMD foo
//
// Set the default command to run in the container (which may be empty).
// Argument handling is the same as RUN.
func dispatchCmd(ctx context.Context, d dispatchRequest, c *instructions.CmdCommand) error {
	runConfig := d.state.runConfig
	cmd, argsEscaped := resolveCmdLine(c.ShellDependantCmdLine, runConfig, d.state.operatingSystem, c.Name(), c.String())

	// We warn here as Windows shell processing operates differently to Linux.
	// Linux:   /bin/sh -c "echo hello" world	--> hello
	// Windows: cmd /s /c "echo hello" world	--> hello world
	if d.state.operatingSystem == "windows" &&
		len(runConfig.Entrypoint) > 0 &&
		d.state.runConfig.ArgsEscaped != argsEscaped {
		fmt.Fprintf(d.builder.Stderr, " ---> [Warning] Shell-form ENTRYPOINT and exec-form CMD may have unexpected results\n")
	}

	runConfig.Cmd = cmd
	runConfig.ArgsEscaped = argsEscaped

	if err := d.builder.commit(ctx, d.state, fmt.Sprintf("CMD %q", cmd)); err != nil {
		return err
	}
	if len(c.ShellDependantCmdLine.CmdLine) != 0 {
		d.state.cmdSet = true
	}

	return nil
}

// HEALTHCHECK foo
//
// Set the default healthcheck command to run in the container (which may be empty).
// Argument handling is the same as RUN.
func dispatchHealthcheck(ctx context.Context, d dispatchRequest, c *instructions.HealthCheckCommand) error {
	runConfig := d.state.runConfig
	if runConfig.Healthcheck != nil {
		oldCmd := runConfig.Healthcheck.Test
		if len(oldCmd) > 0 && oldCmd[0] != "NONE" {
			fmt.Fprintf(d.builder.Stdout, "Note: overriding previous HEALTHCHECK: %v\n", oldCmd)
		}
	}
	runConfig.Healthcheck = c.Health
	return d.builder.commit(ctx, d.state, fmt.Sprintf("HEALTHCHECK %q", runConfig.Healthcheck))
}

// ENTRYPOINT /usr/sbin/nginx
//
// Set the entrypoint to /usr/sbin/nginx. Will accept the CMD as the arguments
// to /usr/sbin/nginx. Uses the default shell if not in JSON format.
//
// Handles command processing similar to CMD and RUN, only req.runConfig.Entrypoint
// is initialized at newBuilder time instead of through argument parsing.
func dispatchEntrypoint(ctx context.Context, d dispatchRequest, c *instructions.EntrypointCommand) error {
	runConfig := d.state.runConfig
	cmd, argsEscaped := resolveCmdLine(c.ShellDependantCmdLine, runConfig, d.state.operatingSystem, c.Name(), c.String())

	// This warning is a little more complex than in dispatchCmd(), as the Windows base images (similar
	// universally to almost every Linux image out there) have a single .Cmd field populated so that
	// `docker run --rm image` starts the default shell which would typically be sh on Linux,
	// or cmd on Windows. The catch to this is that if a dockerfile had `CMD ["c:\\windows\\system32\\cmd.exe"]`,
	// we wouldn't be able to tell the difference. However, that would be highly unlikely, and besides, this
	// is only trying to give a helpful warning of possibly unexpected results.
	if d.state.operatingSystem == "windows" &&
		d.state.runConfig.ArgsEscaped != argsEscaped &&
		((len(runConfig.Cmd) == 1 && strings.ToLower(runConfig.Cmd[0]) != `c:\windows\system32\cmd.exe` && len(runConfig.Shell) == 0) || (len(runConfig.Cmd) > 1)) {
		fmt.Fprintf(d.builder.Stderr, " ---> [Warning] Shell-form CMD and exec-form ENTRYPOINT may have unexpected results\n")
	}

	runConfig.Entrypoint = cmd
	runConfig.ArgsEscaped = argsEscaped
	if !d.state.cmdSet {
		runConfig.Cmd = nil
	}

	return d.builder.commit(ctx, d.state, fmt.Sprintf("ENTRYPOINT %q", runConfig.Entrypoint))
}

// EXPOSE 6667/tcp 7000/tcp
//
// Expose ports for links and port mappings. This all ends up in
// req.runConfig.ExposedPorts for runconfig.
func dispatchExpose(ctx context.Context, d dispatchRequest, c *instructions.ExposeCommand, envs shell.EnvGetter) error {
	// custom multi word expansion
	// expose $FOO with FOO="80 443" is expanded as EXPOSE [80,443]. This is the only command supporting word to words expansion
	// so the word processing has been de-generalized
	ports := []string{}
	for _, p := range c.Ports {
		ps, err := d.shlex.ProcessWords(p, envs)
		if err != nil {
			return err
		}
		ports = append(ports, ps...)
	}
	c.Ports = ports

	ps, _, err := nat.ParsePortSpecs(ports)
	if err != nil {
		return err
	}

	if d.state.runConfig.ExposedPorts == nil {
		d.state.runConfig.ExposedPorts = make(nat.PortSet)
	}
	for p := range ps {
		d.state.runConfig.ExposedPorts[p] = struct{}{}
	}

	return d.builder.commit(ctx, d.state, "EXPOSE "+strings.Join(c.Ports, " "))
}

// USER foo
//
// Set the user to 'foo' for future commands and when running the
// ENTRYPOINT/CMD at container run time.
func dispatchUser(ctx context.Context, d dispatchRequest, c *instructions.UserCommand) error {
	d.state.runConfig.User = c.User
	return d.builder.commit(ctx, d.state, fmt.Sprintf("USER %v", c.User))
}

// VOLUME /foo
//
// Expose the volume /foo for use. Will also accept the JSON array form.
func dispatchVolume(ctx context.Context, d dispatchRequest, c *instructions.VolumeCommand) error {
	if d.state.runConfig.Volumes == nil {
		d.state.runConfig.Volumes = map[string]struct{}{}
	}
	for _, v := range c.Volumes {
		if v == "" {
			return errors.New("VOLUME specified can not be an empty string")
		}
		d.state.runConfig.Volumes[v] = struct{}{}
	}
	return d.builder.commit(ctx, d.state, fmt.Sprintf("VOLUME %v", c.Volumes))
}

// STOPSIGNAL signal
//
// Set the signal that will be used to kill the container.
func dispatchStopSignal(ctx context.Context, d dispatchRequest, c *instructions.StopSignalCommand) error {
	_, err := signal.ParseSignal(c.Signal)
	if err != nil {
		return errdefs.InvalidParameter(err)
	}
	d.state.runConfig.StopSignal = c.Signal
	return d.builder.commit(ctx, d.state, fmt.Sprintf("STOPSIGNAL %v", c.Signal))
}

// ARG name[=value]
//
// Adds the variable foo to the trusted list of variables that can be passed
// to builder using the --build-arg flag for expansion/substitution or passing to 'run'.
// Dockerfile author may optionally set a default value of this variable.
func dispatchArg(ctx context.Context, d dispatchRequest, c *instructions.ArgCommand) error {
	var commitStr strings.Builder
	commitStr.WriteString("ARG ")
	for i, arg := range c.Args {
		if i > 0 {
			commitStr.WriteString(" ")
		}
		commitStr.WriteString(arg.Key)
		if arg.Value != nil {
			commitStr.WriteString("=")
			commitStr.WriteString(*arg.Value)
		}
		d.state.buildArgs.AddArg(arg.Key, arg.Value)
	}

	return d.builder.commit(ctx, d.state, commitStr.String())
}

// SHELL powershell -command
//
// Set the non-default shell to use.
func dispatchShell(ctx context.Context, d dispatchRequest, c *instructions.ShellCommand) error {
	d.state.runConfig.Shell = c.Shell
	return d.builder.commit(ctx, d.state, fmt.Sprintf("SHELL %v", d.state.runConfig.Shell))
}
