# Set tags and upload binaries to GitHub release
# Changes must be committed and pushed to main branch
# make-build.sh must be run to create the build artifacts
# SCRIPT MUST BE RUN FROM ROOT DIRECTORY OF THE REPOSITORY

REL=$(cat latest)
git tag $REL
git push --tags
gh release -R github.com/SpencerBrown-MongoDB/mongodb-tls-certs create $REL --generate-notes  release-binaries/*