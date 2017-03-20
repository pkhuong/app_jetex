FROM python:3.5-alpine

# Only runtime deps here; no need for a build environment.
# Static linking will also help.

# Assume the build step copied everything we need to output/
WORKDIR /jetex_server

# Copy the *directory* CWD (i.e., output/foo becomes /jetex_server/foo).
COPY output/ .

# And running this image should start the server.
CMD ["./hello"]
