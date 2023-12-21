//go:build windows

package libnetwork

func (r *Resolver) setupIPTable() error {
	return nil
}

func (r *Resolver) listenZoneId() string {
	return ""
}
