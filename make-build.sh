# bash script to make tarballs for linux, windows, and macos for releases
# ASSUMES IT'S RUNNING ON lINUX

cd ~/go/src/github.com/SpencerBrown/mongodb-tls-certs/ || exit
go install ./cmd/mongotls
GOOS=windows go install ./cmd/mongotls
GOOS=darwin go install ./cmd/mongotls

cd ~/go/bin || exit
tar czf mongotls-linux.tgz mongotls

cd ~/go/bin/darwin_amd64/ || exit
tar czf mongotls-macos.tgz mongotls

cd ~/go/bin/windows_amd64/ || exit
7za u -tzip mongotls-windows.zip mongotls.exe
