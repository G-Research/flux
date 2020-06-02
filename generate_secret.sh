#!/bin/sh

# Example of generating a secret with an externally
# created ssh key.

ssh-keygen -q -N "" -f identity

ssh-keygen -y -f identity >identity.pub

kubectl -n flux delete secret flux-git-deploy-explicit
kubectl -n flux create secret generic flux-git-deploy-explicit \
  --from-file=identity \
  --from-file=identity.pub 

rm identity identity.pub
