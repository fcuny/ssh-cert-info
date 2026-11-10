package main

import (
	"runtime"
	"runtime/debug"
	"testing"
)

func TestVersionString(t *testing.T) {
	const rev = "ffb84d0e02c692abae48e91feb5dca65bfc94773"
	vcs := func(revision, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: revision},
			{Key: "vcs.modified", Value: modified},
		}
	}

	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "tagged install",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "v0.1.0"}},
			want: "ssh-cert-info v0.1.0 built with go1.27.3",
		},
		{
			name: "pseudo-version from a dirty checkout keeps its own commit",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.3",
				Main:      debug.Module{Version: "v0.0.0-20261109171944-ffb84d0e02c6+dirty"},
				Settings:  vcs(rev, "true"),
			},
			want: "ssh-cert-info v0.0.0-20261109171944-ffb84d0e02c6+dirty built with go1.27.3",
		},
		{
			name: "devel build falls back to the commit",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}, Settings: vcs(rev, "false")},
			want: "ssh-cert-info ffb84d0e02c6 built with go1.27.3",
		},
		{
			name: "devel build marks uncommitted changes",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}, Settings: vcs(rev, "true")},
			want: "ssh-cert-info ffb84d0e02c6+dirty built with go1.27.3",
		},
		{
			name: "devel build without VCS information",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}},
			want: "ssh-cert-info (devel) built with go1.27.3",
		},
		{
			name: "empty version and Go version",
			info: &debug.BuildInfo{},
			want: "ssh-cert-info (devel) built with " + runtime.Version(),
		},
		{
			name: "no build information",
			info: nil,
			want: "ssh-cert-info unknown built with " + runtime.Version(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionString(tt.info); got != tt.want {
				t.Errorf("versionString() = %q, want %q", got, tt.want)
			}
		})
	}
}
