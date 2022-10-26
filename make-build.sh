# Create binaries for mongotls
# Currently works only on Linux with the zip tool installed

rm -r release-binaries
mkdir release-binaries

# Linux on Intel
GOOS=linux GOARCH=amd64 go build ./cmd/mongotls
tar czf release-binaries/mongotls-linux.tar.gz mongotls
rm mongotls

# Windows on Intel
GOOS=windows GOARCH=amd64 go build ./cmd/mongotls
zip release-binaries/mongotls-windows.zip mongotls.exe
rm mongotls.exe

# macOS on Intel
GOOS=darwin GOARCH=amd64 go build ./cmd/mongotls
tar czf release-binaries/mongotls-macos-intel.tar.gz mongotls
rm mongotls

# masOS on Apple Silicon
GOOS=darwin GOARCH=arm64 go build ./cmd/mongotls
tar czf release-binaries/mongotls-macos-apple.tar.gz mongotls
rm mongotls

# Install locally

go install ./cmd/mongotls
printf $(mongotls --version) > latest
