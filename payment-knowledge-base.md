# Payment Knowledge Base

## Purpose

This document is a vendor-neutral knowledge base for payment data, payment cryptography, EMV data, ISO 8583 message content, key-management concepts, HSM concepts, and payment testing artifacts.

It is intended to serve as a canonical base layer that can later absorb provider-specific APIs, tool-specific calculators, network-specific references, and proprietary command sets.

## Core Domains

- Card and account data
- PIN and PIN-block processing
- Card verification values
- EMV and TLV data
- ISO 8583 and transaction messaging
- Cryptograms and transaction authentication
- Key management and cryptographic key types
- HSM command families
- Payment reference data
- Payment testing and developer tooling

## Canonical Entity Types

- `concept`
- `data_element`
- `format`
- `algorithm`
- `operation`
- `artifact`
- `key_type`
- `key_block`
- `command`
- `message_field`
- `reference_list`
- `tool_capability`
- `scheme_variant`
- `constraint_rule`
- `glossary_term`

## Canonical Record Shape

```yaml
id: string
entity_type: concept | data_element | format | algorithm | operation | artifact | key_type | key_block | command | message_field | reference_list | tool_capability | scheme_variant | constraint_rule | glossary_term
canonical_name: string
aliases:
  - string
summary: string
domain:
  - card_data
  - pin_processing
  - card_validation
  - emv
  - iso8583
  - iso20022
  - swift
  - hsm
  - key_management
  - cryptography
  - testing
attributes:
  key: value
relationships:
  - type: uses | derives_from | verifies | encrypts | decrypts | wraps | translates_to | appears_in | related_to | constrained_by
    target_id: string
constraints:
  - string
examples:
  - string
status: active | draft | deprecated
```

## Card Data

### Primary Account Number

```yaml
id: concept.pan
entity_type: data_element
canonical_name: Primary Account Number
aliases:
  - PAN
summary: Primary card number used to identify an account in card-based payment systems.
domain:
  - card_data
  - emv
  - iso8583
attributes:
  common_lengths:
    - 13
    - 16
    - 19
relationships:
  - type: related_to
    target_id: algorithm.luhn
status: active
```

### BIN and IIN

```yaml
id: concept.bin-iin
entity_type: data_element
canonical_name: Bank Identification Number / Issuer Identification Number
aliases:
  - BIN
  - IIN
summary: Leading portion of a PAN used to identify issuer and routing context.
domain:
  - card_data
attributes:
  placement: leading_digits_of_pan
status: active
```

### Expiry Date

```yaml
id: concept.expiry-date
entity_type: data_element
canonical_name: Card Expiry Date
aliases:
  - expiration_date
summary: Date after which the card or application is no longer valid for normal use.
domain:
  - card_data
  - emv
  - card_validation
attributes:
  common_renderings:
    - YYMM
    - MMYY
status: active
```

### Service Code

```yaml
id: concept.service-code
entity_type: data_element
canonical_name: Service Code
aliases:
  - service_code
summary: Three-digit card-service control value used in stripe and card-verification contexts.
domain:
  - card_data
  - card_validation
attributes:
  common_examples:
    stripe_cvv1: "201"
    card_not_present_cvv2: "000"
    chip_context_icvv_or_dcvv: "999"
status: active
```

### Track Data

```yaml
id: format.track1
entity_type: format
canonical_name: Track 1 Data
aliases:
  - track1
summary: Magnetic-stripe data format carrying PAN and cardholder-related information in alphanumeric form.
domain:
  - card_data
status: active
```

```yaml
id: format.track2
entity_type: format
canonical_name: Track 2 Data
aliases:
  - track2
summary: Magnetic-stripe data format carrying PAN, expiry date, service code, and discretionary data in compact numeric form.
domain:
  - card_data
  - iso8583
status: active
```

### Luhn

```yaml
id: algorithm.luhn
entity_type: algorithm
canonical_name: Luhn Algorithm
aliases:
  - modulus_10
  - mod10
summary: Check-digit algorithm commonly used to validate PAN structure.
domain:
  - card_data
  - testing
relationships:
  - type: verifies
    target_id: concept.pan
status: active
```

## PIN and PIN-Block Processing

### PIN

```yaml
id: concept.pin
entity_type: concept
canonical_name: Personal Identification Number
aliases:
  - PIN
summary: Secret numeric credential used to verify cardholder identity in card-present payment flows.
domain:
  - pin_processing
  - cryptography
status: active
```

### Encrypted PIN Block

```yaml
id: artifact.encrypted-pin-block
entity_type: artifact
canonical_name: Encrypted PIN Block
aliases:
  - pin_block
summary: Encrypted representation of a PIN under a defined PIN-block format and encryption key context.
domain:
  - pin_processing
  - cryptography
relationships:
  - type: related_to
    target_id: concept.pin
status: active
```

### PIN Block Format 0

```yaml
id: format.pin-block-format-0
entity_type: format
canonical_name: PIN Block Format 0
aliases:
  - ISO-0
  - ISO 9564-1 Format 0
  - ANSI X9.8
  - VISA-1
  - ECI-1
summary: PAN-dependent PIN-block format built from PIN data and PAN-derived digits before encryption.
domain:
  - pin_processing
  - cryptography
attributes:
  pan_required: true
  pin_length_min: 4
  pin_length_max: 12
  clear_block_length_nibbles: 16
constraints:
  - Uses the right-most 12 PAN digits excluding the check digit.
examples:
  - "041111FFFFFFFFFF XOR 0000642221737511"
status: active
```

### PIN Block Format 1

```yaml
id: format.pin-block-format-1
entity_type: format
canonical_name: PIN Block Format 1
aliases:
  - ISO-1
  - ISO 9564-1 Format 1
  - ECI-4
summary: PAN-independent PIN-block format used when PAN context is not available.
domain:
  - pin_processing
  - cryptography
attributes:
  pan_required: false
  pin_length_min: 4
  pin_length_max: 12
status: active
```

### PIN Block Format 3

```yaml
id: format.pin-block-format-3
entity_type: format
canonical_name: PIN Block Format 3
aliases:
  - ISO-3
  - ISO 9564-1 Format 3
summary: PIN-block format similar to format 0 but using random fill digits.
domain:
  - pin_processing
  - cryptography
attributes:
  pan_required: true
status: active
```

### PIN Block Format 4

```yaml
id: format.pin-block-format-4
entity_type: format
canonical_name: PIN Block Format 4
aliases:
  - ISO-4
  - ISO 9564-1 Format 4
summary: AES-oriented PIN-block format used in newer PIN-processing contexts.
domain:
  - pin_processing
  - cryptography
attributes:
  pan_required: true
  associated_cipher_family: AES
status: active
```

### AS2805 Format 0

```yaml
id: format.as2805-pin-block-format-0
entity_type: format
canonical_name: AS2805 PIN Block Format 0
aliases:
  - AS2805 format 0
summary: Australian-standard PIN-block representation used in payment switching and node-to-node environments.
domain:
  - pin_processing
  - cryptography
status: active
```

### PVV

```yaml
id: artifact.pvv
entity_type: artifact
canonical_name: PIN Verification Value
aliases:
  - PVV
summary: Derived value used to verify a PIN without storing the original PIN.
domain:
  - pin_processing
  - cryptography
attributes:
  common_inputs:
    - PAN
    - PIN
    - PVKI
    - PVK
relationships:
  - type: verifies
    target_id: concept.pin
status: active
```

### PIN Offset

```yaml
id: artifact.pin-offset
entity_type: artifact
canonical_name: PIN Offset
aliases:
  - offset
summary: Derived offset value used in some issuer PIN verification methods, especially IBM 3624-style flows.
domain:
  - pin_processing
  - cryptography
status: active
```

### IBM 3624

```yaml
id: algorithm.ibm-3624
entity_type: algorithm
canonical_name: IBM 3624 PIN Method
aliases:
  - IBM_3624
summary: Family of issuer PIN generation and verification methods using decimalization, offsets, and related derivations.
domain:
  - pin_processing
  - cryptography
status: active
```

### Visa PIN Method

```yaml
id: algorithm.visa-pin
entity_type: algorithm
canonical_name: Visa PIN Verification Method
aliases:
  - Visa PIN
summary: PIN verification family using PVV and issuer PIN verification keys.
domain:
  - pin_processing
  - cryptography
status: active
```

## Card Verification Values

### CVV1

```yaml
id: artifact.cvv1
entity_type: artifact
canonical_name: Card Verification Value 1
aliases:
  - CVV1
  - CVC1
summary: Verification value associated with magnetic-stripe or card-present verification contexts.
domain:
  - card_validation
  - card_data
attributes:
  common_service_code_example: "201"
status: active
```

### CVV2

```yaml
id: artifact.cvv2
entity_type: artifact
canonical_name: Card Verification Value 2
aliases:
  - CVV2
  - CVC2
summary: Printed card verification value commonly used in card-not-present transactions.
domain:
  - card_validation
attributes:
  common_service_code_example: "000"
status: active
```

### iCVV

```yaml
id: artifact.icvv
entity_type: artifact
canonical_name: Integrated Card Verification Value
aliases:
  - iCVV
summary: Verification value associated with EMV chip-based card contexts.
domain:
  - card_validation
  - emv
attributes:
  common_service_code_example: "999"
status: active
```

### dCVV and dCVC

```yaml
id: artifact.dcvv
entity_type: artifact
canonical_name: Dynamic Card Verification Value
aliases:
  - dCVV
  - dCVC
summary: Dynamic verification value tied to changing or transaction-linked card contexts.
domain:
  - card_validation
  - emv
  - cryptography
status: active
```

### CSC

```yaml
id: artifact.csc
entity_type: artifact
canonical_name: Card Security Code
aliases:
  - CSC
summary: Network-specific card security code family commonly overlapping conceptually with CVV2/CVC2 terminology.
domain:
  - card_validation
status: active
```

## EMV and TLV

### BER-TLV

```yaml
id: format.ber-tlv
entity_type: format
canonical_name: BER-TLV
aliases:
  - TLV
  - Tag Length Value
summary: Hierarchical tag-length-value encoding used extensively in EMV payment applications.
domain:
  - emv
  - cryptography
attributes:
  tag_length_bytes: "1-3"
  length_length_bytes: "1-3"
  supports_constructed_tags: true
status: active
```

### EMV Tag

```yaml
id: concept.emv-tag
entity_type: concept
canonical_name: EMV Tag
aliases:
  - TLV tag
summary: Identifying element of an EMV TLV object that names the type of encoded payment data.
domain:
  - emv
status: active
```

### AIP

```yaml
id: data_element.emv-tag-82
entity_type: data_element
canonical_name: Application Interchange Profile
aliases:
  - AIP
  - Tag 82
summary: Bit-mapped EMV value describing card application capabilities.
domain:
  - emv
attributes:
  tag: "82"
  bitmapped: true
status: active
```

### TVR

```yaml
id: data_element.emv-tag-95
entity_type: data_element
canonical_name: Terminal Verification Results
aliases:
  - TVR
  - Tag 95
summary: Bit-mapped EMV value recording terminal-side checks and outcomes during card processing.
domain:
  - emv
attributes:
  tag: "95"
  bitmapped: true
status: active
```

### TSI

```yaml
id: data_element.emv-tag-9b
entity_type: data_element
canonical_name: Transaction Status Information
aliases:
  - TSI
  - Tag 9B
summary: Bit-mapped EMV value indicating which transaction functions were performed.
domain:
  - emv
attributes:
  tag: "9B"
  bitmapped: true
status: active
```

### CVM List

```yaml
id: data_element.emv-tag-8e
entity_type: data_element
canonical_name: Cardholder Verification Method List
aliases:
  - CVM List
  - Tag 8E
summary: Ordered EMV list of supported cardholder verification methods for an application.
domain:
  - emv
attributes:
  tag: "8E"
status: active
```

### Terminal Capabilities

```yaml
id: data_element.emv-tag-9f33
entity_type: data_element
canonical_name: Terminal Capabilities
aliases:
  - Tag 9F33
summary: EMV terminal capability field covering card input, CVM, and security support.
domain:
  - emv
attributes:
  tag: "9F33"
  bitmapped: true
status: active
```

### Additional Terminal Capabilities

```yaml
id: data_element.emv-tag-9f40
entity_type: data_element
canonical_name: Additional Terminal Capabilities
aliases:
  - Tag 9F40
summary: EMV terminal capability field describing additional input/output and processing capabilities.
domain:
  - emv
attributes:
  tag: "9F40"
  bitmapped: true
status: active
```

### TTQ

```yaml
id: data_element.emv-tag-9f66
entity_type: data_element
canonical_name: Terminal Transaction Qualifiers
aliases:
  - TTQ
  - Tag 9F66
summary: Bit-mapped contactless-reader field describing transaction requirements and reader capabilities.
domain:
  - emv
attributes:
  tag: "9F66"
  bitmapped: true
status: active
```

### CTQ

```yaml
id: data_element.emv-tag-9f6c
entity_type: data_element
canonical_name: Card Transaction Qualifiers
aliases:
  - CTQ
  - Tag 9F6C
summary: Bit-mapped card-side field describing contactless and transaction capability details.
domain:
  - emv
attributes:
  tag: "9F6C"
  bitmapped: true
status: active
```

### CID

```yaml
id: data_element.emv-tag-9f27
entity_type: data_element
canonical_name: Cryptogram Information Data
aliases:
  - CID
  - Tag 9F27
summary: EMV field indicating the type of cryptogram returned by the card and associated reader actions.
domain:
  - emv
  - cryptography
attributes:
  tag: "9F27"
  cryptogram_types:
    - TC
    - ARQC
    - AAC
status: active
```

### Selected Common EMV Tags

```yaml
id: reference-list.common-emv-tags
entity_type: reference_list
canonical_name: Common EMV Tags
summary: Frequently encountered EMV tags in transaction debugging and host integration.
domain:
  - emv
attributes:
  examples:
    "5A": PAN
    "5F24": Expiration Date
    "9F02": Amount Authorized
    "9F03": Amount Other
    "9F10": Issuer Application Data
    "9F26": Application Cryptogram
    "82": Application Interchange Profile
    "95": Terminal Verification Results
status: active
```

## EMV Reference Data

### AID

```yaml
id: concept.aid
entity_type: concept
canonical_name: Application Identifier
aliases:
  - AID
summary: Identifier for a payment or smart-card application, typically built on a registered provider namespace.
domain:
  - emv
  - reference_data
relationships:
  - type: related_to
    target_id: concept.rid
status: active
```

### RID

```yaml
id: concept.rid
entity_type: concept
canonical_name: Registered Application Provider Identifier
aliases:
  - RID
summary: Registered namespace prefix used to identify the application provider of an EMV application.
domain:
  - emv
  - reference_data
status: active
```

### ATR

```yaml
id: artifact.atr
entity_type: artifact
canonical_name: Answer To Reset
aliases:
  - ATR
summary: Smart-card reset response used to identify card communication characteristics and sometimes card type.
domain:
  - emv
  - reference_data
status: active
```

### APDU Response

```yaml
id: artifact.apdu-response
entity_type: artifact
canonical_name: APDU Response Status
aliases:
  - APDU response
  - SW1 SW2
summary: Smart-card response status word pair returned after command processing.
domain:
  - emv
  - reference_data
attributes:
  examples:
    "99 00": 1 PIN try left
    "9D 14": Application history list full
status: active
```

### CA Public Key

```yaml
id: artifact.ca-public-key
entity_type: artifact
canonical_name: Certification Authority Public Key
aliases:
  - CA public key
  - CAPK
summary: Public key used in EMV certificate validation chains for offline data authentication and related trust functions.
domain:
  - emv
  - cryptography
  - reference_data
status: active
```

### Issuer EMV Test Key

```yaml
id: artifact.issuer-emv-test-key
entity_type: artifact
canonical_name: Issuer EMV Test Key
aliases:
  - issuer test key
summary: Scheme or test-program key material used for EMV testing and certification workflows.
domain:
  - emv
  - cryptography
  - testing
status: active
```

## Cryptograms and Transaction Authentication

### ARQC

```yaml
id: artifact.arqc
entity_type: artifact
canonical_name: Authorization Request Cryptogram
aliases:
  - ARQC
summary: Cryptogram generated by the card for online transaction authorization.
domain:
  - emv
  - cryptography
  - iso8583
relationships:
  - type: appears_in
    target_id: message_field.iso8583-de55
status: active
```

### ARPC

```yaml
id: artifact.arpc
entity_type: artifact
canonical_name: Authorization Response Cryptogram
aliases:
  - ARPC
summary: Issuer-generated response cryptogram used in online EMV authentication flows.
domain:
  - emv
  - cryptography
  - iso8583
status: active
```

### TC

```yaml
id: artifact.tc
entity_type: artifact
canonical_name: Transaction Certificate
aliases:
  - TC
summary: EMV cryptogram representing an approved offline or completed transaction state.
domain:
  - emv
  - cryptography
status: active
```

### AAC

```yaml
id: artifact.aac
entity_type: artifact
canonical_name: Application Authentication Cryptogram
aliases:
  - AAC
summary: EMV cryptogram representing a declined or rejected application decision path.
domain:
  - emv
  - cryptography
status: active
```

### CAVV

```yaml
id: artifact.cavv
entity_type: artifact
canonical_name: Cardholder Authentication Verification Value
aliases:
  - CAVV
summary: 3-D Secure authentication value used to prove cardholder authentication in e-commerce flows.
domain:
  - card_validation
  - cryptography
status: active
```

### AAV

```yaml
id: artifact.aav
entity_type: artifact
canonical_name: Accountholder Authentication Value
aliases:
  - AAV
summary: Mastercard 3-D Secure authentication artifact analogous to CAVV.
domain:
  - card_validation
  - cryptography
status: active
```

### AEVV

```yaml
id: artifact.aevv
entity_type: artifact
canonical_name: American Express Verification Value
aliases:
  - AEVV
summary: American Express 3-D Secure authentication artifact analogous to CAVV.
domain:
  - card_validation
  - cryptography
status: active
```

## ISO 8583 and Payment Messaging

### ISO 8583 Message

```yaml
id: format.iso8583-message
entity_type: format
canonical_name: ISO 8583 Message
aliases:
  - ISO8583
summary: Standard message structure used for interchange of card-based financial transaction data.
domain:
  - iso8583
attributes:
  common_related_fields:
    - DE2
    - DE35
    - DE52
    - DE55
status: active
```

### MTI

```yaml
id: message_field.iso8583-mti
entity_type: message_field
canonical_name: Message Type Indicator
aliases:
  - MTI
summary: High-level ISO 8583 message classifier defining function and lifecycle stage.
domain:
  - iso8583
status: active
```

### Bitmap

```yaml
id: message_field.iso8583-bitmap
entity_type: message_field
canonical_name: ISO 8583 Bitmap
aliases:
  - bitmap
summary: Presence map indicating which data elements are included in an ISO 8583 message.
domain:
  - iso8583
status: active
```

### DE2

```yaml
id: message_field.iso8583-de2
entity_type: message_field
canonical_name: ISO 8583 Data Element 2
aliases:
  - DE2
summary: Primary Account Number field.
domain:
  - iso8583
relationships:
  - type: related_to
    target_id: concept.pan
status: active
```

### DE35

```yaml
id: message_field.iso8583-de35
entity_type: message_field
canonical_name: ISO 8583 Data Element 35
aliases:
  - DE35
summary: Track 2 data field.
domain:
  - iso8583
relationships:
  - type: related_to
    target_id: format.track2
status: active
```

### DE52

```yaml
id: message_field.iso8583-de52
entity_type: message_field
canonical_name: ISO 8583 Data Element 52
aliases:
  - DE52
summary: PIN-data field, typically carrying encrypted PIN-related content.
domain:
  - iso8583
  - pin_processing
relationships:
  - type: related_to
    target_id: artifact.encrypted-pin-block
status: active
```

### DE55

```yaml
id: message_field.iso8583-de55
entity_type: message_field
canonical_name: ISO 8583 Data Element 55
aliases:
  - DE55
  - ICC System Related Data
summary: Common carrier for EMV TLV data in ISO 8583 transaction messaging.
domain:
  - iso8583
  - emv
relationships:
  - type: related_to
    target_id: format.ber-tlv
  - type: related_to
    target_id: artifact.arqc
status: active
```

### Transaction Message Families

```yaml
id: concept.transaction-message-families
entity_type: concept
canonical_name: Card Transaction Message Families
summary: Common operational groupings used in card payment systems.
domain:
  - iso8583
attributes:
  families:
    - authorization_request
    - authorization_response
    - reversal
    - clearing
    - settlement
    - network_management
status: active
```

## Key Management and Cryptography

### KEK

```yaml
id: key-type.kek
entity_type: key_type
canonical_name: Key Encryption Key
aliases:
  - KEK
summary: Key used to wrap or protect other keys in transit or storage.
domain:
  - key_management
  - cryptography
relationships:
  - type: wraps
    target_id: key_block.tr31
status: active
```

### ZMK

```yaml
id: key-type.zmk
entity_type: key_type
canonical_name: Zone Master Key
aliases:
  - ZMK
summary: Interchange master key commonly used to protect keys exchanged between payment nodes.
domain:
  - key_management
  - cryptography
status: active
```

### PEK

```yaml
id: key-type.pek
entity_type: key_type
canonical_name: PIN Encryption Key
aliases:
  - PEK
summary: Symmetric key used to encrypt and decrypt PIN blocks.
domain:
  - key_management
  - pin_processing
  - cryptography
relationships:
  - type: encrypts
    target_id: artifact.encrypted-pin-block
status: active
```

### PVK

```yaml
id: key-type.pvk
entity_type: key_type
canonical_name: PIN Verification Key
aliases:
  - PVK
summary: Symmetric key used in issuer PIN verification methods such as PVV generation and verification.
domain:
  - key_management
  - pin_processing
  - cryptography
relationships:
  - type: verifies
    target_id: artifact.pvv
status: active
```

### CVK

```yaml
id: key-type.cvk
entity_type: key_type
canonical_name: Card Verification Key
aliases:
  - CVK
summary: Symmetric key used to generate or verify CVV-family values.
domain:
  - key_management
  - card_validation
  - cryptography
status: active
```

### BDK

```yaml
id: key-type.bdk
entity_type: key_type
canonical_name: Base Derivation Key
aliases:
  - BDK
summary: Root derivation key used in DUKPT environments to derive transaction or terminal-specific working keys.
domain:
  - key_management
  - cryptography
relationships:
  - type: derives_from
    target_id: algorithm.dukpt
status: active
```

### IMK

```yaml
id: key-type.imk
entity_type: key_type
canonical_name: Issuer Master Key
aliases:
  - IMK
summary: Root issuer key used in EMV derivation flows for cryptogram and secure messaging operations.
domain:
  - key_management
  - emv
  - cryptography
status: active
```

### Session Key

```yaml
id: key-type.session-key
entity_type: key_type
canonical_name: Session Key
aliases:
  - session_key
summary: Derived key scoped to a transaction, session, or short-lived cryptographic context.
domain:
  - key_management
  - cryptography
status: active
```

### TR-31 Key Block

```yaml
id: key-block.tr31
entity_type: key_block
canonical_name: TR-31 Key Block
aliases:
  - TR31
summary: Key block format used to transport symmetric working keys with metadata and wrapping protection.
domain:
  - key_management
  - cryptography
status: active
```

### TR-34 Key Block

```yaml
id: key-block.tr34
entity_type: key_block
canonical_name: TR-34 Key Block
aliases:
  - TR34
summary: Key transport format used for remote key loading and secure key exchange workflows.
domain:
  - key_management
  - cryptography
status: active
```

### KCV

```yaml
id: artifact.kcv
entity_type: artifact
canonical_name: Key Check Value
aliases:
  - KCV
summary: Short value derived from a key to verify key integrity without exposing key material.
domain:
  - key_management
  - cryptography
attributes:
  common_methods:
    - zeros
    - cmac
    - hash
status: active
```

### DUKPT

```yaml
id: algorithm.dukpt
entity_type: algorithm
canonical_name: Derived Unique Key Per Transaction
aliases:
  - DUKPT
summary: Derivation scheme that produces transaction-specific keys from a base derivation key and key serial number.
domain:
  - key_management
  - cryptography
attributes:
  core_inputs:
    - BDK
    - KSN
status: active
```

### EMV Key Derivation

```yaml
id: algorithm.emv-key-derivation
entity_type: algorithm
canonical_name: EMV Key Derivation
aliases:
  - EMV derivation
summary: Family of EMV issuer and session key derivation methods used for cryptogram generation, authentication, and secure messaging.
domain:
  - emv
  - key_management
  - cryptography
status: active
```

### ECDH Key Exchange

```yaml
id: algorithm.ecdh
entity_type: algorithm
canonical_name: Elliptic Curve Diffie-Hellman Key Exchange
aliases:
  - ECDH
summary: Public-key key-agreement method used to derive shared secrets for short-lived symmetric protection contexts.
domain:
  - key_management
  - cryptography
status: active
```

### Symmetric and Message Authentication Algorithms

```yaml
id: algorithm.des
entity_type: algorithm
canonical_name: Data Encryption Standard
aliases:
  - DES
summary: Legacy symmetric block cipher historically used in payment environments.
domain:
  - cryptography
status: active
```

```yaml
id: algorithm.tdes
entity_type: algorithm
canonical_name: Triple DES
aliases:
  - 3DES
  - TDES
summary: Triple application of DES widely used in legacy and current payment cryptography environments.
domain:
  - cryptography
status: active
```

```yaml
id: algorithm.aes
entity_type: algorithm
canonical_name: Advanced Encryption Standard
aliases:
  - AES
summary: Symmetric block cipher family used in modern payment cryptography.
domain:
  - cryptography
attributes:
  key_sizes:
    - 128
    - 192
    - 256
status: active
```

```yaml
id: algorithm.hmac
entity_type: algorithm
canonical_name: Hash-based Message Authentication Code
aliases:
  - HMAC
summary: Message authentication code construction based on a cryptographic hash and shared secret.
domain:
  - cryptography
status: active
```

```yaml
id: algorithm.mac-iso9797
entity_type: algorithm
canonical_name: ISO 9797-1 MAC
aliases:
  - MAC
  - CBC-MAC
  - Retail MAC
summary: MAC family widely used for payment message integrity and authenticity.
domain:
  - cryptography
attributes:
  common_variants:
    - Algorithm 1
    - Algorithm 3
status: active
```

## HSM Command Families

### HSM Command Reference

```yaml
id: concept.hsm-command-families
entity_type: concept
canonical_name: HSM Command Families
summary: Vendor-specific command sets used to perform cryptographic operations in payment HSMs.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  families:
    - Atalla
    - SafeNet
    - Thales
status: active
```

### Example Thales Commands

```yaml
id: command.thales-a0
entity_type: command
canonical_name: Generate a Key
aliases:
  - A0
summary: Thales HSM command for key generation.
domain:
  - hsm
  - key_management
attributes:
  vendor: Thales
  request_code: A0
  response_code: A1
status: active
```

```yaml
id: command.thales-a6
entity_type: command
canonical_name: Import a Key
aliases:
  - A6
summary: Thales HSM command for importing key material.
domain:
  - hsm
  - key_management
attributes:
  vendor: Thales
  request_code: A6
  response_code: A7
status: active
```

```yaml
id: command.thales-a8
entity_type: command
canonical_name: Export a Key
aliases:
  - A8
summary: Thales HSM command for exporting key material.
domain:
  - hsm
  - key_management
attributes:
  vendor: Thales
  request_code: A8
  response_code: A9
status: active
```

```yaml
id: command.thales-b8
entity_type: command
canonical_name: TR-34 Key Export
aliases:
  - B8
summary: Thales HSM command for TR-34 key export workflows.
domain:
  - hsm
  - key_management
attributes:
  vendor: Thales
  request_code: B8
  response_code: B9
status: active
```

```yaml
id: command.thales-ba
entity_type: command
canonical_name: Encrypt a Clear PIN
aliases:
  - BA
summary: Thales HSM command for encrypting a clear PIN.
domain:
  - hsm
  - pin_processing
  - cryptography
attributes:
  vendor: Thales
  request_code: BA
  response_code: BB
status: active
```

```yaml
id: command.thales-bi
entity_type: command
canonical_name: Generate a BDK
aliases:
  - BI
summary: Thales HSM command for generating a base derivation key.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  vendor: Thales
  request_code: BI
  response_code: BJ
status: active
```

## Payment Testing and Developer Tooling

### Tool Capability Types

```yaml
id: concept.payment-tool-capabilities
entity_type: concept
canonical_name: Payment Tool Capabilities
summary: Common categories of engineering and testing tools used in payment systems work.
domain:
  - testing
  - cryptography
  - emv
  - iso8583
attributes:
  categories:
    - tlv_parser
    - tag_decoder
    - pin_block_calculator
    - pin_extractor
    - pvv_calculator
    - cvv_calculator
    - mac_calculator
    - kcv_generator
    - des_3des_calculator
    - aes_calculator
    - hmac_calculator
    - iso8583_parser
    - iso8583_bitmap_decoder
    - track_generator
    - pan_generator
    - pan_validator
    - apdu_reference
    - aid_reference
    - rid_reference
    - hsm_command_reference
status: active
```

## Cross-Cutting Constraint Rules

### PAN Dependency Rule for PIN-Block Formats

```yaml
id: rule.pin-block-pan-dependency
entity_type: constraint_rule
canonical_name: PIN Block PAN Dependency
summary: Some PIN-block formats require PAN context while others do not.
domain:
  - pin_processing
constraints:
  - Format 0 requires PAN context.
  - Format 1 does not require PAN context.
  - Format 3 requires PAN context.
  - Format 4 requires PAN context.
status: active
```

### CVV Family Rule

```yaml
id: rule.cvv-family-contexts
entity_type: constraint_rule
canonical_name: CVV Family Contexts
summary: Card verification values are context-specific and should not be treated as interchangeable without scheme and channel awareness.
domain:
  - card_validation
constraints:
  - CVV1 is associated with stripe or card-present contexts.
  - CVV2 is associated with card-not-present contexts.
  - iCVV is associated with chip contexts.
  - dCVV and dCVC are dynamic and transaction-linked or context-linked.
status: active
```

### EMV TLV Rule

```yaml
id: rule.emv-tlv-hierarchy
entity_type: constraint_rule
canonical_name: EMV TLV Hierarchy
summary: EMV data is frequently encoded as BER-TLV and may contain nested or constructed objects.
domain:
  - emv
constraints:
  - Tags may be primitive or constructed.
  - TLV structures may be nested.
  - EMV data often appears inside ISO 8583 DE55 for host interchange.
status: active
```

## Reference Catalogs to Materialize Next

- EMV tag catalog
- AID catalog
- RID catalog
- APDU response catalog
- ATR catalog
- CA public key catalog
- issuer EMV test key catalog
- HSM command catalogs by vendor
- ISO 8583 field dictionary
- PIN-block method catalog with aliases and examples

## Sources

When adding records derived from a new source, add a row here. Include enough detail
to re-derive the same records later (document version and date matter for standards
that publish annual revisions).

| Ingested | Source | Publisher | Version / Edition | Domains |
|----------|--------|-----------|-------------------|---------|
| 2026-05-14 | EMV/TLV, cryptography, and PIN-block tool family analysis | Various open tooling | — | card_data, pin_processing, cryptography, emv |
| 2026-05-14 | ISO 8583 parser, bitmap, PIN-block, and EMV-reference tool analysis | Various open tooling | — | iso8583, emv |
| 2026-05-14 | PIN, CVV, PVV, KCV, MAC, DES/3DES, AES, HMAC, and PAN tooling analysis | Various open tooling | — | card_validation, key_management |
| 2026-05-14 | Reference lists: EMV tags, AIDs, RIDs, ATRs, APDU responses, CA public keys, issuer test keys, HSM commands | Various open tooling | — | emv, hsm |
