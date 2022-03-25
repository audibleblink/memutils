package memutils

import (
	"fmt"

	"github.com/audibleblink/logerr"
	"golang.org/x/sys/windows"
)

func init() {
	logerr.SetContext("memutils")
}

// TokenOwner will resolve the primary token or thread owner of the given
// handle
func TokenOwner(hToken windows.Token) (string, error) {
	log := logerr.Add("TokenOwner")
	tokenUser, err := hToken.GetTokenUser()
	if err != nil {
		return "", log.Add("GetTokenUser").Wrap(err)
	}
	user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", log.Add("LookupAccount").Wrap(err)
	}
	return fmt.Sprintf(`%s\%s`, domain, user), err
}

// TokenOwnerFromPid will resolve the primary token or thread owner of the given
// pid
func TokenOwnerFromPid(pid int) (string, error) {
	hToken, err := TokenForPid(pid, windows.TOKEN_QUERY)
	if err != nil {
		return "", logerr.Add("TokenOwnerFromPid").Wrap(err)
	}

	return TokenOwner(hToken)
}

func TokenForPid(pid int, desiredAccess uint32) (tokenH windows.Token, err error) {
	log := logerr.Add("TokenForPid")
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
	if err != nil {
		err = log.Add("OpenProcess").Wrap(err)
		return
	}

	err = windows.OpenProcessToken(hProc, desiredAccess, &tokenH)
	if err != nil {
		err = log.Add("OpenProcessToken").Wrap(err)
	}
	return
}
