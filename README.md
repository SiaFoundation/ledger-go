# ledger-go

[![GoDoc](https://godoc.org/go.sia.tech/ledger-go?status.svg)](https://godoc.org/go.sia.tech/ledger-go)

A Go client library for interacting with the Sia app on Ledger hardware wallets.

## Features

- Open and communicate with Ledger devices over USB (HID) or TCP (for emulator testing)
- Retrieve the app version
- Get public keys and addresses at a given BIP-44 index
- Sign hashes with a device-held private key
- Calculate and display v1/v2 transaction hashes on the device
- Sign v1/v2 transactions on the device

## Installation

```sh
go get go.sia.tech/ledger-go
```

## Usage

```go
device, err := ledger.Open()
if err != nil {
    log.Fatal(err)
}
defer device.Close()

version, err := device.GetVersion()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Sia app version:", version)

addr, err := device.GetAddress(0)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Address:", addr)
```

## License

This project is licensed under the [MIT License](LICENSE).
