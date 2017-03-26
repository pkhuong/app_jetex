# app_jetex
Toy static key-value server

## Building
### reusesocketd
```sh
docker build reusesocketd/
```

### jetex_server
jetex_server creates two images: one is just for building (`build/jetex_server`) and one is for actually running jetex_server (`jetex_server`).

```sh
cd server
./s/build_image
```

## Running

### macOS
```sh
docker-compose docker-compose -f docker-compose.yml -f osx.yml up
```