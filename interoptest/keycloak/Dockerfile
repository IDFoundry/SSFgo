# Never built. .github/workflows/interop-keycloak.yml runs this image with docker
# run, reading the reference from the FROM line below, so the pin lives in
# one place and Dependabot (the docker ecosystem in .github/dependabot.yml)
# can move it. A bump also updates the version in interoptest/README.md.
FROM quay.io/keycloak/keycloak:26.8.2-3@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3
# The image runs Keycloak as an unprivileged user; naming it here only
# keeps this never-built file from defaulting to root.
USER 1000
