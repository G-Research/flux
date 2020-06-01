#!/bin/sh

# Example of generating a secret with an externally
# created ssh key

ssh-keygen -q -N "" -f identity

ssh-keygen -y -f identity >identity.pub
ssh-keygen -l -v -E md5 -f identity >identity.md5
ssh-keygen -l -v -E sha256 -f identity >identity.sha256

kubectl -n flux create secret generic flux-git-deploy-explicit \
  --from-file=identity \
  --from-file=identity.pub \
  --from-file=identity.md5 \
  --from-file=identity.sha256

rm identity identity.pub identity.md5 identity.sha256