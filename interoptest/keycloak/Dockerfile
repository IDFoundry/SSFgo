# Never built. .github/workflows/interop.yml runs this image with docker
# run, reading the reference from the FROM line below, so the pin lives in
# one place and Dependabot (the docker ecosystem in .github/dependabot.yml)
# can move it. A bump also updates the version in interoptest/README.md.
FROM quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc
# The image runs Keycloak as an unprivileged user; naming it here only
# keeps this never-built file from defaulting to root.
USER 1000
