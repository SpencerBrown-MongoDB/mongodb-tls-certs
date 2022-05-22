# Upload binaries to release S3 bucket

awssso --profile  "Support.User-600391573830"
REL=$(cat latest)
aws --profile "Support.User-600391573830" s3 cp release-binaries s3://ts-cloudws-tools/mongotls/$REL/ --recursive
aws --profile Support.User-600391573830 s3 cp latest s3://ts-cloudws-tools/mongotls/
aws --profile Support.User-600391573830 s3 cp README.md s3://ts-cloudws-tools/mongotls/