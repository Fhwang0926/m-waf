//go:build !unix

package agent

import "os"

func auditFileIdentity(os.FileInfo) (uint64, uint64) { return 0, 0 }
