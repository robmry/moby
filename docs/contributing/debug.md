### Debugging the daemon

The Docker daemon and test executables inside the development container can be debugged with [Delve](https://github.com/go-delve/delve).

## Running Docker daemon with debugger attached

1. Change directory, to the root of your Docker repository.

    ```bash
    $ cd moby-fork
    ```

2. Run a development container:
   ```bash
   $ make BIND_DIR=. DOCKER_DEBUG=1 DELVE_PORT=127.0.0.1:2345:2345 shell
   ```
   If you are running Docker Desktop on macOS or Windows, the overlay storage driver will not work
   inside the development container. To use the `vfs` driver, add `DOCKER_GRAPHDRIVER=`. For example:
   ```bash
   $ make BIND_DIR=. DOCKER_GRAPHDRIVER= DOCKER_DEBUG=1 DELVE_PORT=127.0.0.1:2345:2345 shell
   ```
   
   The `BIND_DIR` variable makes your local source code directory available inside the container.

   The `DOCKER_DEBUG` variable disables build optimizations, creating a debuggable binary.

   The Delve backend server listens on a port that needs to be exposed outside the container. It
   is configured using the `DELVE_PORT` environment variable. `DELVE_PORT` accepts the port in
   the same format as Docker CLI's `--publish` (`-p`) option. This means the port can be
   published in multiple ways:

   - `DELVE_PORT=127.0.0.1:2345:2345` - exposes the debugger on port `2345` for local development only (recommended).
   - `DELVE_PORT=2345:2345` - exposes the debugger on port `2345`, without binding to specific IP.
   - `DELVE_PORT=2345` - same as above.

   > **IMPORTANT:** Publishing the port without binding it to localhost (127.0.0.1) might expose
   the debugger outside the developer's machine and is not recommended.

3. Inside the development container:
   1. Build the Docker daemon:
      ```bash
      $ ./hack/make.sh binary-daemon
      ```
   2. Install the newly-built daemon:
      ```bash
      $ make install
      ```
   3. Run the daemon through the `make.sh` script:
      ```bash
      $ ./hack/make.sh run
      ```
      The execution will stop and wait for the IDE or Delve CLI to attach
      to the port, specified with the `DELVE_PORT` variable.
      Once the IDE or Delve CLI is attached, the execution will continue.

## Running integration tests with debugger attached

1. Run development container with build optimizations disabled (ie. `DOCKER_DEBUG=1`) and Delve enabled:

   ```bash
   $ make BIND_DIR=. DOCKER_DEBUG=1 DELVE_PORT=127.0.0.1:2345:2345 shell
   ```
   If you are running Docker Desktop on macOS or Windows, the overlay storage driver will not work
   inside the development container. To use the `vfs` driver, add `DOCKER_GRAPHDRIVER=`. For example:
   ```bash
   $ make BIND_DIR=. DOCKER_GRAPHDRIVER= DOCKER_DEBUG=1 DELVE_PORT=127.0.0.1:2345:2345 shell
   ```
   
2. Inside the development container, run the integration test you want through the `make.sh` script:

   ```bash
   $ TEST_INTEGRATION_DIR=./integration/networking \
       TESTFLAGS='-test.run TestBridgeICC' \
       ./hack/make.sh dynbinary test-integration
   ```

   The execution will pause and wait for the IDE or Delve CLI to attach
   to the port, specified with the `DELVE_PORT` variable.
   Once the IDE or Delve CLI is attached, the test execution will start.

   > **Note:** The debugger attaches to the test executable, not to the Docker daemon the test starts.

## Debugging from IDE (on example of GoLand 2021.3)

1. Open the project in GoLand
2. Click *Add Configuration* on the taskbar
   ![GoLand - adding configuration](images/goland_add_config.png)
3. Create the *Go Remote* configuration. 
   No changes are necessary, unless a different port is to be used.
   ![GoLand - adding remote configuration](images/goland_debug_config.png)
4. Run the Docker binary in the development container, as described in the previous section.
   Make sure that the port in the `DELVE_PORT` variable corresponds to one, used in the *Go Remote* configuration.
5. Run the *Go Remote* configuration.
   The Docker daemon will continue execution inside the container and debugger will stop it on the breakpoints.
   ![GoLand - run Go Remote configuration](images/goland_run_debug_config.png)

## Where to go next

Congratulations, you have experienced how to use Delve to debug the Docker daemon
and how to configure an IDE to make use of it.
