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
    - 8_to_19_digits
    - 13
    - 16
    - 19
  structure:
    leading_component: issuer_identification_number
    trailing_component: account_identifier
    final_component: luhn_check_digit
relationships:
  - type: related_to
    target_id: algorithm.luhn
  - type: related_to
    target_id: concept.iin
status: active
```

### Major Industry Identifier

```yaml
id: concept.mii
entity_type: data_element
canonical_name: Major Industry Identifier
aliases:
  - MII
summary: Leading digit of a payment card number indicating the broad industry category of the issuer.
domain:
  - card_data
relationships:
  - type: related_to
    target_id: concept.pan
status: active
```

### Issuer Identification Number

```yaml
id: concept.iin
entity_type: data_element
canonical_name: Issuer Identification Number
aliases:
  - IIN
  - BIN
summary: Leading portion of a payment card number used to identify the issuing institution or program.
domain:
  - card_data
attributes:
  common_lengths:
    - 6
    - 8
  standard_family: ISO_IEC_7812
relationships:
  - type: related_to
    target_id: concept.mii
  - type: related_to
    target_id: concept.pan
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
summary: Three-digit control value encoded in magnetic-stripe data and related card images that indicates acceptance conditions, cardholder-verification expectations, and authorization requirements.
domain:
  - card_data
  - card_validation
  - emv
attributes:
  common_examples:
    stripe_cvv1: "201"
    card_not_present_cvv2: "000"
    chip_context_icvv_or_dcvv: "999"
  length_digits: 3
  encoding_locations:
    - track1
    - track2
    - magnetic_stripe_image
  digit_semantics:
    first_position:
      purpose: interchange_scope_and_chip_indicator
      examples:
        "1": international
        "2": international_integrated_circuit_card
        "5": national_use_only
        "6": national_use_only_integrated_circuit_card
        "7": private_label_or_proprietary
    second_position:
      purpose: authorization_processing_requirement
      examples:
        "0": normal_authorization
        "2": positive_online_authorization_required
    third_position:
      purpose: cardholder_verification_expectation
      examples:
        "0": pin_required
        "1": normal_cardholder_verification_no_restrictions
        "2": goods_and_services_only_no_cash_back
        "3": atm_only_pin_required
        "5": pin_required_goods_and_services_only_no_cash_back
        "6": prompt_for_pin_if_pin_pad_present
        "7": prompt_for_pin_if_pin_pad_present_goods_and_services_only_no_cash_back
constraints:
  - Service code semantics primarily apply to magnetic-stripe-read processing rather than full chip processing.
  - Values of 2 or 6 in the first position are commonly used to indicate integrated-circuit-card contexts.
  - Not every syntactically possible three-digit combination is a valid network-approved service code.
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

### PIN Block Format 2

```yaml
id: format.pin-block-format-2
entity_type: format
canonical_name: PIN Block Format 2
aliases:
  - ISO-2
  - ISO 9564-1 Format 2
summary: PIN-block format intended for local offline use, especially smart-card-oriented contexts.
domain:
  - pin_processing
  - cryptography
attributes:
  pan_required: false
  offline_local_use_only: true
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
summary: >
  Legacy issuer PIN generation and verification method using single-DES encryption, a
  decimalization table, and a PIN offset. The offset is stored by the issuer and compared
  during online PIN verification without storing or transmitting the clear PIN.
domain:
  - pin_processing
  - cryptography
attributes:
  cipher: single_DES_ECB
  inputs:
    PVK: 16-byte or 24-byte DES key (PIN Verification Key)
    decimalization_table: 16-digit string mapping hex nibbles 0-F to decimal digits
    validation_data: issuer-supplied digits (typically 12 rightmost PAN digits excl check digit), padded to 16 nibbles with pad character
    pad_character: single hex nibble used to right-pad validation data (commonly F)
    pin_length: 4-12 digits
  natural_pin_derivation:
    step_1: Build 16-nibble validation block — validation_data padded to 16 nibbles
    step_2: Single-DES ECB encrypt the validation block with PVK
    step_3: Decimalize — map each nibble of the encrypted output through decimalization_table
    step_4: Natural PIN = leftmost pin_length digits of decimalized result
  offset_generation:
    for_each_digit_i: offset[i] = (desired_pin[i] - natural_pin[i] + 10) mod 10
  verification:
    step_1: Re-derive natural PIN from stored keying material
    step_2: Reconstruct expected PIN — expected[i] = (natural_pin[i] + stored_offset[i]) mod 10
    step_3: Compare reconstructed PIN to presented PIN
  apc_equivalent: GeneratePinData / VerifyPinData with IBM_3624 pinVerificationMethod
  security_note: >
    Single DES and clear-key design; not suitable for new implementations.
    Use VISA PVV or EMV-based PIN methods for new issuer systems.
relationships:
  - type: related_to
    target_id: artifact.pin-offset
  - type: related_to
    target_id: key-type.pvk
constraints:
  - Decimalization table must be exactly 16 decimal digits (one per nibble 0-F)
  - Validation data is padded with the pad character to reach 16 nibbles before encryption
  - Natural PIN and stored offset together disclose the clear PIN; both must be protected
  - Natural PIN derivation is fully deterministic for fixed keying material
status: active
```

### Visa PIN Method

```yaml
id: algorithm.visa-pin
entity_type: algorithm
canonical_name: Visa PIN Verification Value Method
aliases:
  - Visa PIN
  - PVV method
  - VISA PVV
summary: >
  Issuer PIN verification method that produces a 4-digit PIN Verification Value (PVV) from
  the PIN, PAN, and a PVK. The PVV is stored by the issuer and compared during online
  authorization without storing or transmitting the clear PIN.
domain:
  - pin_processing
  - cryptography
attributes:
  cipher: single_DES_ECB
  inputs:
    PVK: 16-byte or 24-byte DES key, selected by PVKI
    PVKI: PIN Verification Key Index, 1-6; embedded in PVV input and selects which key
    PAN: cardholder account number
    PIN: 4-12 digit PIN
  pvv_derivation_steps:
    step_1: >
      Build 8-byte PVV input = PVKI digit (1 nibble) + 11 rightmost PAN digits excluding
      Luhn check digit (11 nibbles) + first PIN digit (1 nibble) = 16 hex nibbles / 8 bytes
    step_2: DES-ECB encrypt PVV input using the PVK indexed by PVKI
    step_3: >
      Two-pass decimalization (see rule.pvv-decimalization): scan encrypted result
      left-to-right collecting decimal digits (0-9); if fewer than 4 found, rescan mapping
      A=0 B=1 C=2 D=3 E=4 F=5
    step_4: PVV = first 4 collected digits
  apc_equivalent: GeneratePinData / VerifyPinData with VISA_PVV pinVerificationMethod
  stored_value: 4 decimal digit PVV stored by issuer; compared during online PIN authorization
relationships:
  - type: related_to
    target_id: artifact.pvv
  - type: related_to
    target_id: key-type.pvk
  - type: related_to
    target_id: rule.pvv-decimalization
constraints:
  - PVKI is 1 digit (1-6); it is the first nibble of the PVV input and determines which PVK is used
  - The 11 PAN digits exclude the Luhn check digit (rightmost digit of the PAN)
  - The two-pass decimalization is mandatory per Visa spec; single-pass produces incorrect PVV
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

### Card Security Code Family

```yaml
id: concept.card-security-code-family
entity_type: concept
canonical_name: Card Security Code Family
aliases:
  - CSC
  - CVC
  - CVV
  - CID
summary: Family of printed or electronically generated card security values used primarily in card-not-present and anti-fraud contexts.
domain:
  - card_validation
  - card_data
attributes:
  common_form_factors:
    - printed_three_digit
    - printed_four_digit
    - electronically_generated_dynamic_value
relationships:
  - type: related_to
    target_id: artifact.cvv1
  - type: related_to
    target_id: artifact.cvv2
  - type: related_to
    target_id: artifact.icvv
  - type: related_to
    target_id: artifact.dcvv
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

### American Express CSC1 (Classic)

```yaml
id: artifact.amex-csc1
entity_type: artifact
canonical_name: American Express Card Security Code Version 1
aliases:
  - CSC1
  - Amex CID Classic
summary: >
  Amex classic card security code. Uses the CVV algorithm with the card's actual service
  code (not forced to 000). Printed on the card face; 3-5 digits.
domain:
  - card_validation
  - card_data
attributes:
  algorithm: CVV (DES-based, same as CVV1/CVV2)
  service_code_behavior: card service code used as-is
  digits: 3-5
  apc_generation_attribute: AmexCardSecurityCodeVersion1
  key_usage: TR31_C0_CARD_VERIFICATION_KEY (TDES_2KEY)
relationships:
  - type: related_to
    target_id: artifact.cvv2
  - type: related_to
    target_id: concept.card-security-code-family
status: active
```

### American Express CSC2 (Enhanced)

```yaml
id: artifact.amex-csc2
entity_type: artifact
canonical_name: American Express Card Security Code Version 2
aliases:
  - CSC2
  - Amex CID Enhanced
summary: >
  Amex enhanced card security code. Uses the CVV algorithm with service code forced to 000
  (same convention as CVV2 and iCVV). Base algorithm for iCSC and AEVV. Typically printed
  as a 4-digit value on the card face.
domain:
  - card_validation
  - card_data
attributes:
  algorithm: CVV with service_code forced to 000
  digits: 4
  apc_generation_attribute: AmexCardSecurityCodeVersion2
  key_usage: TR31_C0_CARD_VERIFICATION_KEY (TDES_2KEY)
relationships:
  - type: related_to
    target_id: artifact.cvv2
  - type: related_to
    target_id: artifact.amex-icsc
  - type: related_to
    target_id: artifact.amex-aevv
  - type: related_to
    target_id: concept.card-security-code-family
status: active
```

### American Express iCSC

```yaml
id: artifact.amex-icsc
entity_type: artifact
canonical_name: American Express Integrated Card Security Code
aliases:
  - iCSC
summary: >
  Amex chip-card analog of iCVV. Uses the CSC2 algorithm (CVV with service code override)
  to produce a card-present security value that differs from the printed CSC2, preventing
  replay of magnetic-stripe data on chip-capable cards.
domain:
  - card_validation
  - emv
attributes:
  algorithm: CSC2 (CVV with service code override)
  service_code_contact: "999"
  service_code_contactless: "702"
  apc_generation_attribute: AmexCardSecurityCodeVersion2
  key_usage: TR31_C0_CARD_VERIFICATION_KEY (TDES_2KEY)
relationships:
  - type: related_to
    target_id: artifact.icvv
  - type: related_to
    target_id: artifact.amex-csc2
status: active
```

### American Express AEVV

```yaml
id: artifact.amex-aevv
entity_type: artifact
canonical_name: American Express Electronic Commerce Verification Value
aliases:
  - AEVV
summary: >
  Amex 3-D Secure authentication value equivalent to CAVV. Uses the CSC2 algorithm
  with field repurposing: random number in the expiry date field; authentication
  results code + two-factor code in the service code field. Always 3 digits.
domain:
  - card_validation
  - cryptography
attributes:
  algorithm: CSC2 (CVV-family with repurposed input fields)
  expiry_field_value: random_number
  service_code_field_value: authentication_results_code + two_factor_code
  output_length: 3 digits
  apc_generation_attribute: AmexCardSecurityCodeVersion2
  key_usage: TR31_C0_CARD_VERIFICATION_KEY (TDES_2KEY)
relationships:
  - type: related_to
    target_id: artifact.cavv
  - type: related_to
    target_id: artifact.amex-csc2
  - type: related_to
    target_id: operation.three-d-secure
status: active
```

### Mastercard DCVC3

```yaml
id: artifact.mastercard-dcvc3
entity_type: artifact
canonical_name: Mastercard Dynamic Card Verification Code 3
aliases:
  - DCVC3
summary: >
  Mastercard dynamic card verification value for contactless and chip transactions.
  Derived from PAN, PSN, Track 1/2 service fields, unpredictable number, and ATC
  using an EMV master key for dynamic numbers (E4).
domain:
  - card_validation
  - emv
attributes:
  inputs: [PAN, PSN, track_service_fields, unpredictable_number, ATC]
  key_usage: TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS (DeriveKey=true)
  apc_generation_attribute: DynamicCardVerificationCode3
relationships:
  - type: related_to
    target_id: artifact.dcvv
  - type: related_to
    target_id: artifact.arqc
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

### Smart Card

```yaml
id: concept.smart-card
entity_type: concept
canonical_name: Smart Card
aliases:
  - chip card
  - integrated circuit card
  - ICC
summary: Card with an integrated circuit capable of storing data and performing controlled cryptographic or application operations.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: concept.emv-standard
status: active
```

### ISO/IEC 7816

```yaml
id: concept.iso7816
entity_type: concept
canonical_name: ISO/IEC 7816
aliases:
  - ISO 7816
summary: Standard family for contact smart cards covering physical characteristics, electrical interface, transmission protocols, and interchange commands.
domain:
  - emv
  - cryptography
attributes:
  notable_parts:
    - Part 1 Physical Characteristics
    - Part 2 Contact Dimensions and Location
    - Part 3 Electrical Interface and Transmission Protocols
    - Part 4 Organization, Security, and Commands for Interchange
relationships:
  - type: related_to
    target_id: concept.smart-card
status: active
```

### APDU

```yaml
id: format.apdu
entity_type: format
canonical_name: Application Protocol Data Unit
aliases:
  - APDU
summary: Smart-card command/response message format used for interchange with integrated circuit cards, including EMV card interactions.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: concept.iso7816
  - type: related_to
    target_id: artifact.apdu-response
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

### Practical EMV Tag Catalog

```yaml
id: reference-list.practical-emv-tag-catalog
entity_type: reference_list
canonical_name: Practical EMV Tag Catalog
summary: High-value EMV tags commonly used in transaction decoding, issuer-host integration, and EMV troubleshooting.
domain:
  - emv
attributes:
  tags:
    - tag: "4F"
      name: Application Identifier
      aliases:
        - AID
      category: application_selection
      typical_meaning: Identifies the payment application selected on the card.
    - tag: "50"
      name: Application Label
      category: application_selection
      typical_meaning: Human-readable application label.
    - tag: "57"
      name: Track 2 Equivalent Data
      category: card_data
      typical_meaning: EMV representation of track 2 style card data.
    - tag: "5A"
      name: Application Primary Account Number
      aliases:
        - PAN
      category: card_data
      typical_meaning: Card account number in EMV data.
    - tag: "5F24"
      name: Application Expiration Date
      category: card_data
      typical_meaning: Expiration date of the application.
    - tag: "5F25"
      name: Application Effective Date
      category: card_data
      typical_meaning: Date from which the application becomes valid.
    - tag: "5F28"
      name: Issuer Country Code
      category: issuer_data
      typical_meaning: Issuer country identifier.
    - tag: "5F2A"
      name: Transaction Currency Code
      category: transaction_context
      typical_meaning: Currency code used for the transaction.
    - tag: "5F34"
      name: Application PAN Sequence Number
      category: card_data
      typical_meaning: Distinguishes cards sharing the same PAN.
    - tag: "5F36"
      name: Transaction Currency Exponent
      category: transaction_context
      typical_meaning: Currency decimal scaling information.
    - tag: "82"
      name: Application Interchange Profile
      aliases:
        - AIP
      category: terminal_card_capabilities
      typical_meaning: Card application capabilities expressed as a bit map.
    - tag: "84"
      name: Dedicated File Name
      aliases:
        - DDF Name
      category: application_selection
      typical_meaning: Name of a directory or application file.
    - tag: "8A"
      name: Authorisation Response Code
      category: online_processing
      typical_meaning: Issuer or host response code reflected into EMV processing.
    - tag: "8C"
      name: Card Risk Management Data Object List 1
      aliases:
        - CDOL1
      category: data_object_lists
      typical_meaning: Data objects required by the card for first action analysis.
    - tag: "8D"
      name: Card Risk Management Data Object List 2
      aliases:
        - CDOL2
      category: data_object_lists
      typical_meaning: Data objects required by the card for second action analysis.
    - tag: "8E"
      name: Cardholder Verification Method List
      aliases:
        - CVM List
      category: cardholder_verification
      typical_meaning: Ordered list of cardholder verification methods supported by the application.
    - tag: "8F"
      name: Certification Authority Public Key Index
      category: offline_data_authentication
      typical_meaning: Selects the certification authority public key used for issuer certificate validation.
    - tag: "90"
      name: Issuer Public Key Certificate
      category: offline_data_authentication
      typical_meaning: Certificate binding the issuer public key to the issuer.
    - tag: "92"
      name: Issuer Public Key Remainder
      category: offline_data_authentication
      typical_meaning: Remaining bytes of the issuer public key when not fully encoded in the certificate.
    - tag: "93"
      name: Signed Static Application Data
      aliases:
        - SSAD
      category: offline_data_authentication
      typical_meaning: Signed static application data used in static data authentication.
    - tag: "94"
      name: Application File Locator
      aliases:
        - AFL
      category: application_processing
      typical_meaning: Record map telling the terminal what application data to read.
    - tag: "95"
      name: Terminal Verification Results
      aliases:
        - TVR
      category: risk_and_decisioning
      typical_meaning: Bit map of terminal-side checks and results.
    - tag: "97"
      name: Transaction Certificate Data Object List
      aliases:
        - TDOL
      category: data_object_lists
      typical_meaning: Data objects to be included when generating a transaction certificate.
    - tag: "9A"
      name: Transaction Date
      category: transaction_context
      typical_meaning: Date of the transaction.
    - tag: "9B"
      name: Transaction Status Information
      aliases:
        - TSI
      category: risk_and_decisioning
      typical_meaning: Bit map indicating which transaction functions were performed.
    - tag: "9C"
      name: Transaction Type
      category: transaction_context
      typical_meaning: Indicates purchase, cash, refund, and related transaction types.
    - tag: "9F02"
      name: Amount, Authorised
      category: transaction_context
      typical_meaning: Primary authorised amount.
    - tag: "9F03"
      name: Amount, Other
      category: transaction_context
      typical_meaning: Cashback or secondary amount.
    - tag: "9F10"
      name: Issuer Application Data
      aliases:
        - IAD
      category: issuer_data
      typical_meaning: Issuer-controlled EMV data used in host and card risk logic.
    - tag: "9F1A"
      name: Terminal Country Code
      category: terminal_context
      typical_meaning: Country code of the terminal.
    - tag: "9F1E"
      name: Interface Device Serial Number
      category: terminal_context
      typical_meaning: Terminal or interface serial number.
    - tag: "9F26"
      name: Application Cryptogram
      category: cryptograms
      typical_meaning: Card-generated cryptogram such as ARQC, TC, or AAC.
    - tag: "9F27"
      name: Cryptogram Information Data
      aliases:
        - CID
      category: cryptograms
      typical_meaning: Indicates the type of cryptogram returned by the card.
    - tag: "9F33"
      name: Terminal Capabilities
      category: terminal_context
      typical_meaning: Bit map of terminal-supported input, CVM, and security features.
    - tag: "9F34"
      name: Cardholder Verification Method Results
      aliases:
        - CVMR
      category: cardholder_verification
      typical_meaning: Result of the CVM processing path chosen during the transaction.
    - tag: "9F35"
      name: Terminal Type
      category: terminal_context
      typical_meaning: Encoded description of terminal environment and capabilities.
    - tag: "9F36"
      name: Application Transaction Counter
      aliases:
        - ATC
      category: cryptograms
      typical_meaning: Card-side transaction counter incremented by the application.
    - tag: "9F37"
      name: Unpredictable Number
      aliases:
        - UN
      category: cryptograms
      typical_meaning: Terminal-generated nonce used in cryptogram generation.
    - tag: "9F41"
      name: Transaction Sequence Counter
      category: terminal_context
      typical_meaning: Terminal-side transaction sequencing value.
    - tag: "9F53"
      name: Transaction Category Code
      category: transaction_context
      typical_meaning: Additional transaction classification metadata.
    - tag: "9F66"
      name: Terminal Transaction Qualifiers
      aliases:
        - TTQ
      category: contactless
      typical_meaning: Contactless terminal capability and requirement map.
    - tag: "9F6C"
      name: Card Transaction Qualifiers
      aliases:
        - CTQ
      category: contactless
      typical_meaning: Contactless card-side qualifier map.
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

### EMVCo

```yaml
id: concept.emvco
entity_type: concept
canonical_name: EMVCo
summary: Industry body that manages EMV specifications and related payment technology standards such as EMV 3-D Secure.
domain:
  - emv
  - reference_data
relationships:
  - type: related_to
    target_id: concept.emv-standard
  - type: related_to
    target_id: operation.three-d-secure
status: active
```

### EMV Standard

```yaml
id: concept.emv-standard
entity_type: concept
canonical_name: EMV Standard
aliases:
  - EMV
summary: Technical standard family for integrated-circuit payment cards, terminals, and related transaction processing.
domain:
  - emv
attributes:
  common_books:
    - Book 1 Interface Requirements
    - Book 2 Security and Key Management
    - Book 3 Application Specification
    - Book 4 Cardholder, Attendant, and Acquirer Interface Requirements
relationships:
  - type: related_to
    target_id: concept.emvco
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
  - cryptography
attributes:
  communication_purposes:
    - proposed_communication_parameters
    - card_nature_and_state
  common_variants:
    - cold_atr
    - warm_atr
relationships:
  - type: related_to
    target_id: concept.iso7816
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
summary: Card-generated EMV cryptogram sent for online authorization so that the issuer or its processor can validate that the transaction context was produced by a card holding the correct issuer-derived keys.
domain:
  - emv
  - cryptography
  - iso8583
attributes:
  common_inputs:
    - application_transaction_counter
    - unpredictable_number
    - transaction_amount_and_context_data
    - card_or_application_profile_data
    - issuer_derived_cryptogram_key
  produced_by:
    - chip_card
  verified_by:
    - issuer
    - issuer_processor
  common_outputs:
    - authorization_request_cryptogram_value
  verifier_explanation:
    - The issuer side can validate the ARQC because it can derive the same session or application cryptogram key from issuer master material plus card-specific transaction data.
    - The verifier does not need the card's private internals; it needs the correct issuer-side derivation inputs and transaction context.
relationships:
  - type: appears_in
    target_id: message_field.iso8583-de55
  - type: related_to
    target_id: algorithm.emv-key-derivation
status: active
```

### Full-Chip Data

```yaml
id: artifact.full-chip-data
entity_type: artifact
canonical_name: Full-Chip Data
aliases:
  - full_chip_data
summary: EMV transaction data set that meets minimum chip requirements, supports online cryptographic validation, and records the card-terminal interaction performed during the transaction.
domain:
  - emv
  - cryptography
  - iso8583
attributes:
  defining_characteristics:
    - conforms_to_emvco_minimum_requirements
    - supports_online_cryptographic_validation
    - records_card_and_terminal_interactions
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: message_field.iso8583-de55
status: active
```

### Magnetic-Stripe Image

```yaml
id: artifact.magnetic-stripe-image
entity_type: artifact
canonical_name: Magnetic-Stripe Image
aliases:
  - magnetic_stripe_image
summary: Minimum chip-resident payment data that replicates magnetic-stripe content needed to process an EMV-compliant transaction.
domain:
  - emv
  - card_data
attributes:
  replicated_elements_commonly_include:
    - pan_related_data
    - expiration_date
    - service_code
    - discretionary_data_subset
relationships:
  - type: related_to
    target_id: concept.service-code
  - type: related_to
    target_id: format.track2
status: active
```

### Fallback Transaction

```yaml
id: operation.fallback-transaction
entity_type: operation
canonical_name: Fallback Transaction
aliases:
  - emv_fallback
  - chip_fallback
summary: Transaction that begins as a chip-read attempt but is completed using an alternate capture path because the terminal could not successfully read the chip.
domain:
  - emv
  - iso8583
  - card_validation
attributes:
  common_alternate_capture_paths:
    - magnetic_stripe_read
    - manual_entry
relationships:
  - type: related_to
    target_id: artifact.full-chip-data
  - type: related_to
    target_id: artifact.magnetic-stripe-image
  - type: related_to
    target_id: format.track2
constraints:
  - Fallback should be distinguished from normal magnetic-stripe processing because the transaction originally began as a chip path.
status: active
```

### Derivation Key Index

```yaml
id: data_element.derivation-key-index
entity_type: data_element
canonical_name: Derivation Key Index
aliases:
  - DKI
summary: Numeric value personalized into a chip card to indicate which key should be used for authentication or encryption functions in scheme-specific EMV processing.
domain:
  - emv
  - cryptography
attributes:
  common_role: key_selection_hint
relationships:
  - type: related_to
    target_id: artifact.arqc
status: active
```

### Unique Derivation Key

```yaml
id: key_type.unique-derivation-key
entity_type: key_type
canonical_name: Unique Derivation Key
aliases:
  - UDK
summary: Scheme-specific key used in application-cryptogram generation and authentication flows.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: artifact.arqc
status: active
```

### Visa Chip Authenticate Service

```yaml
id: operation.visa-chip-authenticate-service
entity_type: operation
canonical_name: Visa Chip Authenticate Service
summary: Visa service that authenticates an application cryptogram, returns the authentication result to a requesting party or stand-in processing, and may generate an authenticated response cryptogram.
domain:
  - emv
  - cryptography
  - iso8583
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: artifact.arpc
status: active
```

### ARPC

```yaml
id: artifact.arpc
entity_type: artifact
canonical_name: Authorization Response Cryptogram
aliases:
  - ARPC
summary: Issuer-generated EMV response cryptogram returned so the card can validate that the authorization response originated from an entity holding the proper issuer-side cryptographic material.
domain:
  - emv
  - cryptography
  - iso8583
attributes:
  common_inputs:
    - arqc_or_arqc_validation_context
    - issuer_response_code_or_response_data
    - issuer_derived_response_key_or_session_key
  produced_by:
    - issuer
    - issuer_processor
  verified_by:
    - chip_card
  card_explanation:
    - The card can validate the ARPC because it can derive or reference the same response-cryptogram context from its chip-resident keying material and transaction state.
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: algorithm.emv-key-derivation
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

### 3-D Secure

```yaml
id: operation.three-d-secure
entity_type: operation
canonical_name: 3-D Secure
aliases:
  - 3DS
  - 3D Secure
  - EMV 3-D Secure
summary: Authentication protocol for online card transactions involving merchant/acquirer, issuer, and interoperability domains.
domain:
  - card_validation
  - cryptography
  - iso8583
attributes:
  three_domains:
    - acquirer_domain
    - issuer_domain
    - interoperability_domain
  major_generations:
    - 3DS1
    - 3DS2
relationships:
  - type: related_to
    target_id: artifact.cavv
  - type: related_to
    target_id: artifact.aav
  - type: related_to
    target_id: artifact.aevv
status: active
```

### Contactless Payment

```yaml
id: operation.contactless-payment
entity_type: operation
canonical_name: Contactless Payment
aliases:
  - tap_to_pay
summary: Payment interaction performed in close proximity using a contactless card, device, or tokenized mobile wallet over short-range radio technology.
domain:
  - emv
  - card_validation
  - cryptography
attributes:
  transport_technologies:
    - RFID
    - NFC
  related_standards:
    - ISO_IEC_14443
  common_form_factors:
    - contactless_card
    - key_fob
    - smartphone
    - wearable
relationships:
  - type: related_to
    target_id: concept.smart-card
  - type: related_to
    target_id: concept.tokenization
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

### Processing Code

```yaml
id: message_field.iso8583-de3
entity_type: message_field
canonical_name: ISO 8583 Data Element 3
aliases:
  - DE3
  - Processing Code
summary: Transaction processing classifier used to indicate the operational intent of a message.
domain:
  - iso8583
status: active
```

### Transaction Amount

```yaml
id: message_field.iso8583-de4
entity_type: message_field
canonical_name: ISO 8583 Data Element 4
aliases:
  - DE4
  - Amount Transaction
summary: Transaction amount field used to carry the financial amount of the request or advice.
domain:
  - iso8583
status: active
```

### Transmission Date and Time

```yaml
id: message_field.iso8583-de7
entity_type: message_field
canonical_name: ISO 8583 Data Element 7
aliases:
  - DE7
  - Transmission Date and Time
summary: Network transmission timestamp used for routing, ordering, and host-side processing.
domain:
  - iso8583
status: active
```

### STAN

```yaml
id: message_field.iso8583-de11
entity_type: message_field
canonical_name: ISO 8583 Data Element 11
aliases:
  - DE11
  - STAN
  - System Trace Audit Number
summary: Trace number used to correlate requests, responses, reversals, and audit events.
domain:
  - iso8583
status: active
```

### Local Transaction Time

```yaml
id: message_field.iso8583-de12
entity_type: message_field
canonical_name: ISO 8583 Data Element 12
aliases:
  - DE12
  - Local Transaction Time
summary: Local terminal transaction time, commonly encoded as hhmmss.
domain:
  - iso8583
status: active
```

### Local Transaction Date

```yaml
id: message_field.iso8583-de13
entity_type: message_field
canonical_name: ISO 8583 Data Element 13
aliases:
  - DE13
  - Local Transaction Date
summary: Local terminal transaction date, commonly encoded as MMDD.
domain:
  - iso8583
status: active
```

### Expiration Date Field

```yaml
id: message_field.iso8583-de14
entity_type: message_field
canonical_name: ISO 8583 Data Element 14
aliases:
  - DE14
  - Expiration Date
summary: Card expiration date field carried in transaction messages.
domain:
  - iso8583
relationships:
  - type: related_to
    target_id: concept.expiry-date
status: active
```

### Merchant Category Code

```yaml
id: message_field.iso8583-de18
entity_type: message_field
canonical_name: ISO 8583 Data Element 18
aliases:
  - DE18
  - Merchant Type
  - Merchant Category Code
  - MCC
summary: Merchant classification field used for network processing, routing, risk, and reporting.
domain:
  - iso8583
status: active
```

### POS Entry Mode

```yaml
id: message_field.iso8583-de22
entity_type: message_field
canonical_name: ISO 8583 Data Element 22
aliases:
  - DE22
  - POS Entry Mode
summary: Field describing how card data was captured and what verification or terminal capabilities applied.
domain:
  - iso8583
  - emv
attributes:
  frequently_encodes:
    - card_reading_method
    - cardholder_verification_method
    - terminal_capabilities
status: active
```

### Response Code

```yaml
id: message_field.iso8583-de39
entity_type: message_field
canonical_name: ISO 8583 Data Element 39
aliases:
  - DE39
  - Response Code
summary: Outcome code used by hosts and networks to indicate approval, denial, or processing conditions.
domain:
  - iso8583
attributes:
  example_values:
    "00": approved
    "05": do_not_honor
    "14": invalid_card_number
status: active
```

### ISO 8583 Field Definition Model

```yaml
id: concept.iso8583-field-model
entity_type: concept
canonical_name: ISO 8583 Field Definition Model
summary: Message-field model where each data element has a meaning, content type, and fixed or variable length, while networks may overlay private usage.
domain:
  - iso8583
attributes:
  common_content_types:
    - n
    - a
    - an
    - b
  common_length_styles:
    - fixed
    - llvar
    - lllvar
status: active
```

### ISO 8583 Versioning

```yaml
id: concept.iso8583-versioning
entity_type: concept
canonical_name: ISO 8583 Versioning
summary: Evolution of the ISO 8583 standard across 1987, 1993, and 2003 releases with stable message framing but shifting field definitions and usage.
domain:
  - iso8583
attributes:
  major_versions:
    - "1987"
    - "1993"
    - "2003"
  message_capacity:
    original_standard: up_to_128_data_elements
    later_releases: up_to_192_data_elements
status: active
```

### Practical ISO 8583 Field Dictionary

```yaml
id: reference-list.practical-iso8583-field-dictionary
entity_type: reference_list
canonical_name: Practical ISO 8583 Field Dictionary
summary: High-value ISO 8583 fields commonly needed for parsing, message mapping, switching, authorization, and payment troubleshooting.
domain:
  - iso8583
attributes:
  fields:
    - de: "1"
      name: Secondary Bitmap
      category: message_structure
      typical_meaning: Extends the message field map beyond the primary 64 elements.
    - de: "2"
      name: Primary Account Number
      aliases:
        - PAN
      category: card_data
      typical_meaning: Card account number used in routing and authorization.
    - de: "3"
      name: Processing Code
      category: transaction_classification
      typical_meaning: Indicates transaction function such as purchase, withdrawal, transfer, or refund.
    - de: "4"
      name: Amount, Transaction
      category: financial_amount
      typical_meaning: Primary financial amount of the message.
    - de: "7"
      name: Transmission Date and Time
      category: timing
      typical_meaning: Network transmission timestamp.
    - de: "11"
      name: System Trace Audit Number
      aliases:
        - STAN
      category: correlation
      typical_meaning: Trace number used for request/response matching and audit.
    - de: "12"
      name: Local Transaction Time
      category: timing
      typical_meaning: Local terminal transaction time.
    - de: "13"
      name: Local Transaction Date
      category: timing
      typical_meaning: Local terminal transaction date.
    - de: "14"
      name: Expiration Date
      category: card_data
      typical_meaning: Expiration date of the card used in the transaction.
    - de: "18"
      name: Merchant Category Code
      aliases:
        - MCC
      category: merchant_context
      typical_meaning: Merchant business classification.
    - de: "22"
      name: POS Entry Mode
      category: terminal_context
      typical_meaning: Indicates card capture method and verification context.
    - de: "23"
      name: Card Sequence Number
      category: card_data
      typical_meaning: Distinguishes cards sharing the same PAN.
    - de: "25"
      name: POS Condition Code
      category: terminal_context
      typical_meaning: Indicates transaction condition such as normal presentment or recurring context.
    - de: "32"
      name: Acquiring Institution Identification Code
      category: routing
      typical_meaning: Identifies the acquirer or acquiring institution.
    - de: "35"
      name: Track 2 Data
      category: card_data
      typical_meaning: Track 2 or track 2 equivalent content used in magstripe and fallback flows.
    - de: "37"
      name: Retrieval Reference Number
      aliases:
        - RRN
      category: correlation
      typical_meaning: End-to-end reference value used for retrieval and reconciliation.
    - de: "38"
      name: Authorization Identification Response
      category: authorization
      typical_meaning: Approval or authorization identifier returned by the issuer or network.
    - de: "39"
      name: Response Code
      category: authorization
      typical_meaning: Outcome code indicating approval, denial, or processing status.
    - de: "41"
      name: Card Acceptor Terminal Identification
      aliases:
        - Terminal ID
      category: terminal_context
      typical_meaning: Identifies the accepting terminal.
    - de: "42"
      name: Card Acceptor Identification Code
      aliases:
        - Merchant ID
      category: merchant_context
      typical_meaning: Identifies the merchant or accepting entity.
    - de: "43"
      name: Card Acceptor Name and Location
      category: merchant_context
      typical_meaning: Human-readable merchant name and location record.
    - de: "49"
      name: Transaction Currency Code
      category: financial_amount
      typical_meaning: Currency of the transaction amount.
    - de: "52"
      name: PIN Data
      category: pin_processing
      typical_meaning: Encrypted PIN-related data, commonly an encrypted PIN block.
    - de: "53"
      name: Security Related Control Information
      category: cryptography
      typical_meaning: Security control metadata such as key-set or algorithm context.
    - de: "55"
      name: ICC System Related Data
      aliases:
        - DE55
      category: emv
      typical_meaning: BER-TLV EMV payload carried between terminal and host.
    - de: "60"
      name: Reserved National
      category: private_or_national_use
      typical_meaning: Network- or country-specific extension field.
    - de: "61"
      name: Reserved Private
      category: private_or_national_use
      typical_meaning: Private network extension field.
    - de: "62"
      name: Reserved Private
      category: private_or_national_use
      typical_meaning: Private network extension field.
    - de: "63"
      name: Reserved Private
      category: private_or_national_use
      typical_meaning: Private network extension field.
    - de: "64"
      name: Message Authentication Code
      aliases:
        - MAC
      category: cryptography
      typical_meaning: Primary MAC protecting message authenticity and integrity.
    - de: "70"
      name: Network Management Information Code
      category: network_management
      typical_meaning: Indicates the network-management function being performed.
    - de: "90"
      name: Original Data Elements
      category: reversal_and_reconciliation
      typical_meaning: Carries original message references used in reversals and follow-on processing.
    - de: "95"
      name: Replacement Amounts
      category: financial_amount
      typical_meaning: Adjusted or replacement financial amounts.
    - de: "100"
      name: Receiving Institution Identification Code
      category: routing
      typical_meaning: Identifies the receiving institution for the message.
    - de: "102"
      name: Account Identification 1
      category: account_context
      typical_meaning: Primary account reference used in transfers and account-linked flows.
    - de: "103"
      name: Account Identification 2
      category: account_context
      typical_meaning: Secondary account reference used in transfers and paired-account flows.
    - de: "128"
      name: Message Authentication Code
      aliases:
        - Secondary MAC
      category: cryptography
      typical_meaning: End-of-message MAC used in extended-bitmap variants.
status: active
```

### Card-Present and Card-Not-Present

```yaml
id: concept.transaction-channel-context
entity_type: concept
canonical_name: Transaction Channel Context
summary: High-level distinction between transactions where the card is physically present and those where it is not.
domain:
  - iso8583
  - card_validation
attributes:
  channels:
    - card_present
    - card_not_present
relationships:
  - type: related_to
    target_id: artifact.cvv1
  - type: related_to
    target_id: artifact.cvv2
  - type: related_to
    target_id: operation.three-d-secure
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
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### IPEK

```yaml
id: key-type.ipek
entity_type: key_type
canonical_name: Initial PIN Encryption Key
aliases:
  - IPEK
  - IK
summary: Device initialization key derived from a base derivation key and injected into a DUKPT-capable device to seed future transaction keys.
domain:
  - key_management
  - pin_processing
  - cryptography
relationships:
  - type: derives_from
    target_id: key-type.bdk
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### KSN

```yaml
id: artifact.ksn
entity_type: artifact
canonical_name: Key Serial Number
aliases:
  - KSN
summary: DUKPT transaction identifier that carries device and transaction-counter information needed to regenerate the transaction key on the receiving side.
domain:
  - key_management
  - cryptography
  - pin_processing
attributes:
  canonical_size_bits: 80
  typical_components:
    - key_set_id
    - device_identifier
    - transaction_counter
  transaction_counter_size_bits: 21
relationships:
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### Future Key

```yaml
id: key-type.future-key
entity_type: key_type
canonical_name: Future Key
aliases:
  - future_key
summary: Pre-derived device-resident DUKPT key material consumed to derive a one-time transaction key and then invalidated.
domain:
  - key_management
  - cryptography
  - pin_processing
relationships:
  - type: derives_from
    target_id: key-type.ipek
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### Transaction Key

```yaml
id: key-type.transaction-key
entity_type: key_type
canonical_name: Transaction Key
aliases:
  - session_key
  - one_time_key
summary: One-time or transaction-scoped working key derived for a single DUKPT operation.
domain:
  - key_management
  - cryptography
relationships:
  - type: derives_from
    target_id: key-type.future-key
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### Transaction Counter

```yaml
id: data_element.dukpt-transaction-counter
entity_type: data_element
canonical_name: DUKPT Transaction Counter
aliases:
  - transaction_counter
summary: Device-side counter component of the DUKPT derivation state used to select a unique transaction key for each operation and communicate that selection to the receiving side through the KSN.
domain:
  - key_management
  - cryptography
attributes:
  size_bits: 21
  approximate_capacity: over_1000000_transactions
  roles:
    - device_advances_counter_per_transaction
    - counter_position_is_encoded_in_ksn
    - receiver_uses_counter_position_to_reconstruct_same_transaction_key
relationships:
  - type: related_to
    target_id: artifact.ksn
  - type: related_to
    target_id: key-type.transaction-key
status: active
```

### Device Identifier in DUKPT

```yaml
id: data_element.dukpt-device-identifier
entity_type: data_element
canonical_name: DUKPT Device Identifier
aliases:
  - TRSM_ID
  - device_id
summary: Device-unique identifier component carried in the KSN to distinguish one originating device from another within a derivation domain.
domain:
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: artifact.ksn
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

### KDH

```yaml
id: glossary.kdh
entity_type: glossary_term
canonical_name: Key Distribution Host
aliases:
  - KDH
summary: Sending-side role in remote key-distribution workflows that originates or exports key material toward a receiving device or service.
domain:
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: glossary.krd
  - type: related_to
    target_id: key-block.tr34
status: active
```

### KRD

```yaml
id: glossary.krd
entity_type: glossary_term
canonical_name: Key Receiving Device
aliases:
  - KRD
summary: Receiving-side role in remote key-distribution workflows that imports or unwraps transported key material.
domain:
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: glossary.kdh
  - type: related_to
    target_id: key-block.tr34
status: active
```

### TR-31 Key Block

```yaml
id: key-block.tr31
entity_type: key_block
canonical_name: TR-31 Key Block
aliases:
  - TR31
summary: Structured symmetric-key transport format that carries a wrapped key together with usage and algorithm metadata so the receiving side knows how the imported key may be used.
domain:
  - key_management
  - cryptography
attributes:
  participant_inputs:
    sender_holds:
      - clear_or_hsm_resident_working_key
      - wrapping_key_or_kbpk
      - key_usage_and_algorithm_metadata
    receiver_holds:
      - same_wrapping_key_or_kbpk
  common_contents:
    - wrapped_symmetric_key
    - usage_metadata
    - algorithm_metadata
    - mode_of_use_metadata
  exchanged_material:
    - tr31_key_block
  receiver_explanation:
    - The receiving side can unwrap the transported key because it holds the same KEK or KBPK used to protect the block.
    - The metadata in the block tells the receiver what kind of key is being imported and the permitted usage context.
  common_outputs:
    - imported_working_key
    - recovered_key_attributes
constraints:
  - Vendor-specific transport wrappers or indicator prefixes are not necessarily part of the portable TR-31 block and may need to be removed before import into another system.
status: active
```

### TR-34 Key Block

```yaml
id: key-block.tr34
entity_type: key_block
canonical_name: TR-34 Key Block
aliases:
  - TR34
summary: Remote key-loading and asymmetric key-transport format that lets a sending side deliver symmetric key material to a receiving side using certificate-based trust, protected transport, and authenticated payload structure.
domain:
  - key_management
  - cryptography
attributes:
  common_roles:
    - kdh
    - krd
  participant_inputs:
    kdh_holds:
      - key_to_be_transported
      - signing_key_or_certificate_context
    krd_holds:
      - private_key_matching_its_transport_certificate
      - trusted_certificate_context
  structural_layers:
    - signed_data_wrapper
    - enveloped_data_wrapper
    - recipient_certificate_identification
    - encrypted_ephemeral_or_transport_material
    - encrypted_key_block
  authentication_attributes_commonly_include:
    - content_type
    - random_nonce
    - tr31_header
    - message_digest
  exchanged_material:
    - signed_tr34_payload
    - sender_and_receiver_certificate_references
  receiver_explanation:
    - The receiving side can recover the transported secret material because it holds the private key that matches the certificate referenced for the recipient.
    - The signed and authenticated structure lets the receiver verify who sent the payload and whether the protected contents were altered.
  common_outputs:
    - recovered_symmetric_key_material
    - verified_transport_context
relationships:
  - type: related_to
    target_id: glossary.kdh
  - type: related_to
    target_id: glossary.krd
  - type: related_to
    target_id: artifact.tr34-credential-id
status: active
```

### TR-34 Credential ID

```yaml
id: artifact.tr34-credential-id
entity_type: artifact
canonical_name: TR-34 Credential Identifier
aliases:
  - TR-34 credential ID
  - TR34 credential ID
  - cred_id
summary: Certificate identifier used in TR-34 structures to reference a signing or receiving certificate, commonly represented as the certificate issuer together with the certificate serial number.
domain:
  - key_management
  - cryptography
attributes:
  common_components:
    - certificate_issuer
    - certificate_serial_number
relationships:
  - type: related_to
    target_id: key-block.tr34
status: active
```

### KCV

```yaml
id: artifact.kcv
entity_type: artifact
canonical_name: Key Check Value
aliases:
  - KCV
summary: Short comparison value derived from a key to confirm that two systems hold the same key material without exposing the key itself.
domain:
  - key_management
  - cryptography
attributes:
  common_methods:
    - ansi_x9_24_ecb_zeros
    - cmac
    - hash
  common_visible_lengths_hex:
    - 4
    - 6
  interoperability_notes:
    - The same key can produce different KCVs under different calculation methods.
    - Operational comparisons usually use only the leftmost displayed hex characters rather than the full derived value.
    - A KCV is meaningful only when both parties agree on the calculation method and visible length.
  method_notes:
    ansi_x9_24_ecb_zeros:
      common_usage: legacy_tdes_and_hsm_interoperability
      description: Encrypt an all-zero block under the key and compare a leftmost truncated portion of the result.
    cmac:
      common_usage: aes_key_check_values
      description: Derive the check value using CMAC rather than the older ECB-zeros convention.
    hash:
      common_usage: some_non_hsm_or_vendor_specific_flows
      description: Compare a truncated portion of a hash-derived value when the workflow defines KCV that way.
constraints:
  - Do not compare KCVs across systems unless the method and truncation length are known to match.
  - AES key workflows should not assume legacy ANSI X9.24 ECB-zeros KCV semantics.
status: active
```

### KCV Validation Rule

```yaml
id: rule.kcv-validation-after-transfer
entity_type: constraint_rule
canonical_name: KCV Validation After Key Transfer
summary: Key transport and import workflows should compare key check values before and after transfer to confirm that the receiving side imported the intended key material.
domain:
  - key_management
  - cryptography
constraints:
  - Compare KCVs across exporting and importing systems whenever both sides expose a compatible KCV method.
  - Compare the same visible hex length on both sides; common operational lengths are 4 or 6 hex characters.
  - Treat a KCV mismatch as evidence of translation, wrapping, integrity, or key-selection failure until proven otherwise.
status: active
```

### Format-Preserving Encryption

```yaml
id: algorithm.format-preserving-encryption
entity_type: algorithm
canonical_name: Format-Preserving Encryption
aliases:
  - FPE
summary: Encryption approach that preserves the original data format, commonly discussed for protecting payment identifiers such as PANs.
domain:
  - cryptography
  - card_data
relationships:
  - type: related_to
    target_id: concept.pan
status: active
```

### Tokenization

```yaml
id: concept.tokenization
entity_type: concept
canonical_name: Tokenization
summary: Replacement of a sensitive payment identifier with a surrogate token for storage, display, or transmission.
domain:
  - card_data
  - cryptography
relationships:
  - type: related_to
    target_id: concept.pan
status: active
```

### DUKPT

```yaml
id: algorithm.dukpt
entity_type: algorithm
canonical_name: Derived Unique Key Per Transaction
aliases:
  - DUKPT
summary: Key-management scheme that produces transaction-specific working keys from a base derivation key and device transaction state.
domain:
  - key_management
  - cryptography
attributes:
  core_inputs:
    - BDK
    - KSN
    - transaction_counter
  key_management_not_encryption: true
  historical_block_cipher_family: TDES
  current_recommended_family: AES
  receiver_state_model: stateless_except_for_bdk_selection
  receiver_derivation_behavior:
    - parse_device_identifier_and_counter_position_from_ksn
    - derive_same_transaction_key_used_by_originating_device
  originator_state_model:
    - transaction_counter
    - future_keys
    - device_identifier
  common_uses:
    - PIN_encryption
    - message_authentication
    - transaction_data_encryption
relationships:
  - type: related_to
    target_id: key-type.bdk
  - type: related_to
    target_id: key-type.ipek
  - type: related_to
    target_id: artifact.ksn
  - type: related_to
    target_id: data_element.dukpt-transaction-counter
  - type: related_to
    target_id: key-type.future-key
  - type: related_to
    target_id: key-type.transaction-key
status: active
```

### AES DUKPT Official Test Vectors (ANSI X9.24-3-2017)

```yaml
id: artifact.ansi-x9-24-3-test-vectors
entity_type: artifact
canonical_name: ANSI X9.24-3-2017 Official AES DUKPT Test Vectors
aliases:
  - X9.24-3 Test Vectors
  - AES DUKPT Test Vectors
summary: >
  Official supplement to ANSI X9.24-3-2017 (ASC X9, Jan 2018) providing normative test vectors
  for validating AES DUKPT implementations. Covers five key-size combinations, eleven transaction
  counter values from 1 to 0xFFFFFFFF, and AES Format 4 PIN block construction examples.
domain:
  - key_management
  - cryptography
  - testing
attributes:
  source_url: http://x9.org/standards/x9-24-part-3-test-vectors/
  pdf_url: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf
  python_source_zip: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Python-Source-20180129.zip
  suites_covered:
    - AES-128 keys from AES-128 BDK
    - AES-128 keys from AES-256 BDK
    - AES-256 keys from AES-256 BDK
    - 2-key TDEA keys from AES-128 BDK
    - 3-key TDEA keys from AES-128 BDK
  counter_values_tested:
    - counters 1–8 (first eight transactions)
    - 131070 (0x1fffe) and 131071 (0x1ffff), last counters before first bit-skip
    - 131072 (0x20000) and 131073 (0x20001), first skipped-bit counters
    - 8675309 (0x845fed), random midrange sample
    - 4294844416 (0xfffe2000) through 4294901760 (0xffff0000), last five active counters
    - 4294967295 (0xffffffff), DUKPT Update Key renewal counter
  common_inputs:
    BDK_128: FEDCBA9876543210F1F1F1F1F1F1F1F1
    BDK_256: FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1
    InitialKeyID: "1234567890123456"
  initial_keys:
    IK_AES128_from_AES128_BDK: 1273671EA26AC29AFA4D1084127652A1
    IK_AES256_from_AES256_BDK: CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F
    notes:
      - 2TDEA and 3TDEA suites share IK_AES128_from_AES128_BDK as their initial key.
      - AES-128-from-AES-256-BDK suite shares IK_AES256_from_AES256_BDK as its initial key.
      - Derivation keys at a given counter are identical across all suites that share the same IK.
  derivation_data_structure:
    description: >
      16 bytes. Bytes 0–7 encode the key-type descriptor; bytes 8–11 are the last 4 bytes of
      InitialKeyID (the device identifier half); bytes 12–15 are the 32-bit transaction counter
      (big-endian). Only bytes 12–15 vary per transaction.
    byte_layout:
      byte_0_version: "0x01 (always)"
      byte_1_key_size_class:
        "0x01": 128-bit output key (AES-128, 2TDEA)
        "0x02": 192/256-bit output key (3TDEA, AES-256)
      bytes_2_3_key_purpose:
        "0x0002": Key Encryption Key (KEK)
        "0x1000": Encrypt-only (PIN encryption / data encryption encrypt)
        "0x1001": Decrypt-only (data encryption decrypt)
        "0x1002": Bidirectional (data encryption both ways)
        "0x2000": MAC generation
        "0x2001": MAC verification
        "0x2002": MAC both ways
        "0x8000": Key Derivation Key
      bytes_4_5_algorithm:
        "0x0000": 2-key TDEA
        "0x0001": 3-key TDEA
        "0x0002": AES-128
        "0x0004": AES-256
      bytes_6_7_key_length_bits_big_endian:
        "0x0080": 128 bits
        "0x00C0": 192 bits (3TDEA)
        "0x0100": 256 bits (AES-256)
      bytes_8_11: Last 4 bytes of 8-byte InitialKeyID
      bytes_12_15: Transaction counter, 32-bit big-endian
    examples:
      AES128_PIN_encrypt_counter_1:   "01011000 00020080 90123456 00000001"
      AES128_MAC_generation_counter_1: "01012000 00020080 90123456 00000001"
      AES128_data_encrypt_counter_1:  "01013000 00020080 90123456 00000001"
      AES128_KEK_counter_1:           "01010002 00020080 90123456 00000001"
      AES128_DUKPT_update_key:        "01010002 00020080 90123456 FFFFFFFF"
      AES256_PIN_encrypt_counter_1:   "01021000 00040100 90123456 00000001"
      AES256_DUKPT_update_key:        "01020002 00040100 90123456 FFFFFFFF"
      TDEA2_PIN_encrypt_counter_1:    "01011000 00000080 90123456 00000001"
      TDEA2_DUKPT_update_key:         "01010002 00000080 90123456 FFFFFFFF"
      TDEA3_PIN_encrypt_counter_1:    "01021000 000100C0 90123456 00000001"
      TDEA3_DUKPT_update_key:         "01010002 00000080 90123456 FFFFFFFF"
  reference_vectors_AES128_from_AES128_BDK:
    initial_key: 1273671EA26AC29AFA4D1084127652A1
    counter_1:
      derivation_key:              4F21B565BAD9835E112B6465635EAE44
      PIN_encryption_key:          AF8CB133A78F8DC2D1359F18527593FB
      MAC_generation_key:          A2DC23DE6FDE0824A2BC321E08E4B8B7
      data_encryption_encrypt:     A35C412EFD41FDB98B69797C02DCD08F
      key_encryption_key:          36A724B7BEFA5A25F5E7B5782A4554A2
    counter_8:
      derivation_key:              718EE6CF0B27E53D5F7AF99C4D8146A2
      PIN_encryption_key:          4D9DF3FBEE3448FC3E676D04320A90F5
      MAC_generation_key:          6FD572E5D59E618875F193484F9178FB
      data_encryption_encrypt:     650F34204ABD4E57764D61AC3D266FB1
    DUKPT_update_key_0xFFFFFFFF:
      derivation_key:              36C6EBBCC0536FC91C1D50660D4F82AE
      key_encryption_key:          9A9770AEE1ACD1B13473D0463A1883B9
  reference_vectors_AES256_from_AES256_BDK:
    initial_key: CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F
    counter_1:
      derivation_key:              54AC2B32B145EA4A554CB8BC44B17467063A799856B1CCC2A138D36E8DBF78B3
      PIN_encryption_key:          8C1AB7BEE973829E30242E0BBBDD4946D540C98FC1B5BDCF94790001A23FD502
      MAC_generation_key:          61DABDF4B340CF461EE860B1D1AB55357142BD2D6977306859CF49AEFE8F1549
      data_encryption_encrypt:     71EB36C9A6B7F801D1D1700C29741FC5A5C4E9B45D742DA7AF6992B8AA29AF58
    DUKPT_update_key_0xFFFFFFFF:
      derivation_key:              39064FDC8373D710AFAA823E757E59190C92DD8FBF86B87B673632F4E04C97D2
      key_encryption_key:          AEFB210C136278A1279F7C8815F446DB8EBE2AA910B157AA4E6484D8DE9C4807
  reference_vectors_2TDEA_from_AES128_BDK:
    initial_key: 1273671EA26AC29AFA4D1084127652A1
    counter_1:
      derivation_key:              4F21B565BAD9835E112B6465635EAE44
      PIN_encryption_key:          630C706D9546E47D4449313F61C4D4AB
      MAC_generation_key:          5D8FD787E8A796D07035FFCA9B5800BB
      data_encryption_encrypt:     BD44121C223F831446A01EE3A4CB58D2
    DUKPT_update_key_0xFFFFFFFF:
      derivation_key:              36C6EBBCC0536FC91C1D50660D4F82AE
      key_encryption_key:          4744A5ECBC62B5C4BB76FBEAE1E244A3
  reference_vectors_3TDEA_from_AES128_BDK:
    initial_key: 1273671EA26AC29AFA4D1084127652A1
    counter_1:
      derivation_key:              4F21B565BAD9835E112B6465635EAE44
      PIN_encryption_key:          EA8B3F37EB9B15831167EF2977FD8762D9B5913F35766F6A
      MAC_generation_key:          2A1061A6EAC2C14FAC3758EA07B3648A624B24E942785BF1
      data_encryption_encrypt:     F716DFBC6B2D2D5825B694EEEE181A013F2F1C09380BBE0C
    DUKPT_update_key_0xFFFFFFFF:
      derivation_key:              36C6EBBCC0536FC91C1D50660D4F82AE
      key_encryption_key:          4744A5ECBC62B5C4BB76FBEAE1E244A3
  format_4_pin_block_example:
    PAN: "4111111111111111"
    PIN: "1234"
    random_bytes: 2F69ADDE2E9E7ACE
    plaintext_PIN_field:  441234AAAAAAAAAA2F69ADDE2E9E7ACE
    plaintext_PAN_field:  44111111111111111000000000000000
    field_construction:
      PIN_field: "0x44 | PIN_length_nibble | PIN_digits | 0xA_padding | 8_random_bytes"
      PAN_field: "0x44 | 12_rightmost_PAN_digits_before_check_digit | 0x1 | zero_pad_to_16_bytes"
    encryption_algorithm:
      step_1: "Block_A = AES_ECB_encrypt(PIN_key, PIN_field XOR PAN_field)"
      step_2: "Encrypted_PIN_Block = AES_ECB_encrypt(PIN_key, Block_A XOR PAN_field)"
      note: Double-pass encryption; PAN field XOR'd in as a tweak in both rounds.
    transaction_1_PIN_key_AF8CB133A78F8DC2D1359F18527593FB:
      intermediate_block_A:  DE84127CF6DCA7DFE47BDE89057CB820
      intermediate_block_B:  9A95036DE7CDB6CEF47BDE89057CB820
      encrypted_PIN_block:   A912150391AB65A67E52883D81CE2D15
    transaction_2_PIN_key_D30BDC73EC9714B000BEC66BDB7B6D09:
      intermediate_block_A:  37489F3DB975A040CD1EEE9E68051A44
      intermediate_block_B:  73598E2CA864B151DD1EEE9E68051A44
      encrypted_PIN_block:   52A00503BD34BA1383F6A7EE9FE2547F
constraints:
  - All vectors are normative for ANSI X9.24-3-2017 compliance testing.
  - The DUKPT Update Key (counter 0xFFFFFFFF) always uses a 128-bit key regardless of working-key
    size; 2TDEA and 3TDEA suites share the same Update Key derivation data and result.
  - For AES-128 from AES-256 BDK, derivation keys at each counter are identical to AES-256 from
    AES-256 BDK (same IK); only the output transaction key size differs (AES-128 vs AES-256).
  - The Python reference ZIP at the X9 URL generates extended traces for all counters and suites.
relationships:
  - type: related_to
    target_id: algorithm.dukpt
  - type: related_to
    target_id: tool.cyberchef-payment-fork
status: active
```

### Master/Session Key Management

```yaml
id: algorithm.master-session
entity_type: algorithm
canonical_name: Master/Session Key Management
aliases:
  - Master/Session
summary: Older key-management approach in which each device is initialized with a unique master key and transaction data is protected with session keys derived under that device context.
domain:
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### Tamper-Resistant Security Module

```yaml
id: concept.trsm
entity_type: concept
canonical_name: Tamper-Resistant Security Module
aliases:
  - TRSM
summary: Security module designed to protect sensitive cryptographic key material within a tamper-resistant boundary.
domain:
  - hsm
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: key-type.bdk
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
attributes:
  common_inputs:
    - issuer_master_key
    - pan_and_pan_sequence_number_or_other_card_identity_data
    - application_transaction_counter_or_transaction_context
    - scheme_specific_derivation_mode
  common_outputs:
    - card_specific_master_key
    - session_key
    - cryptogram_key
    - secure_messaging_key
  issuer_side_explanation:
    - The issuer side can verify card cryptograms because it starts from issuer master material and applies the same derivation inputs the card uses or was personalized with.
    - The card does not need to send its derived keys; both sides independently derive matching values from shared derivation rules and transaction context.
  common_uses:
    - arqc_generation_and_verification
    - arpc_generation
    - issuer_script_mac
    - issuer_script_confidentiality
relationships:
  - type: related_to
    target_id: key-type.imk
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: artifact.arpc
status: active
```

### ECDH Key Exchange

```yaml
id: algorithm.ecdh
entity_type: algorithm
canonical_name: Elliptic Curve Diffie-Hellman Key Exchange
aliases:
  - ECDH
summary: Public-key key-agreement method in which two parties exchange public keys and independently derive the same shared secret from their own private key plus the other party's public key.
domain:
  - key_management
  - cryptography
attributes:
  participant_inputs:
    each_party_holds:
      - private_key
      - own_public_key
    each_party_receives:
      - counterparty_public_key
  exchanged_material:
    - public_keys_only
  derived_outputs:
    - shared_secret
    - symmetric_key_or_kek_after_key_derivation
  receiver_explanation:
    - The receiving side can derive the same shared secret because it has its own private key and the sender's public key.
    - The sender derives the same shared secret from its private key and the receiver's public key.
    - Matching shared-secret results are possible without either side revealing its private key.
  common_payment_uses:
    - short_lived_key_agreement_for_key_transport
    - ecdh_wrapped_tr31_exchange
constraints:
  - ECDH by itself establishes shared secret material; a separate derivation or wrapping step typically turns that secret into an operational symmetric key or KEK.
  - Exchanging public keys does not let an observer derive the shared secret without one of the private keys.
relationships:
  - type: related_to
    target_id: key-block.tr31
  - type: related_to
    target_id: key-block.tr34
status: active
```

### Master/Session Key Management

```yaml
id: algorithm.master-session
entity_type: algorithm
canonical_name: Master/Session Key Management
aliases:
  - Master/Session
summary: Older key-management approach in which each device is initialized with a unique master key and transaction data is protected with session keys derived under that device context.
domain:
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: algorithm.dukpt
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
summary: MAC family widely used for payment message integrity and authenticity. Algorithm 1 (CBC-MAC) and Algorithm 3 (Retail MAC) are legacy; CMAC (Algorithm 5) is the preferred choice for new deployments.
domain:
  - cryptography
attributes:
  variants:
    Algorithm1_CBC_MAC:
      tr31_key_usage: M1
      apc_enum_direct: ISO9797_ALGORITHM1
      apc_enum_dukpt: DukptIso9797Algorithm1
      security_note: >
        Vulnerable to length-extension attacks for variable-length messages: an attacker who
        knows MAC(m) can derive MAC(m‖padded_block) without the key. Safe only when all
        inputs are a fixed, pre-agreed length (e.g., a single 8-byte block). Use requires
        Legacy Constraint Protocol confirmation — prefer CMAC unless counterparty forces it.
      forced_choice_scenario: Counterparty network (e.g., older acquirer host) has not migrated from ANSI X9.9.
    Algorithm3_Retail_MAC:
      tr31_key_usage: M3
      apc_enum_direct: ISO9797_ALGORITHM3
      apc_enum_dukpt: DukptIso9797Algorithm3
      standard: ANSI X9.19
      security_note: >
        Two-key TDES construction (encrypt K1, decrypt K2, re-encrypt K1). Birthday-bound
        concern: after approximately 2^32 MAC computations with the same key, statistical
        collisions become feasible. Still mandated by some legacy acquirer networks and
        regional switches. Apply Legacy Constraint Protocol when used. Schedule key rotation
        to stay well below the birthday bound.
      forced_choice_scenario: Counterparty network (e.g., regional switch, older processor) requires ANSI X9.19 and does not support CMAC.
    Algorithm5_CMAC:
      tr31_key_usage: M6
      apc_enum_direct: CMAC
      apc_enum_dukpt: DukptCmac
      security_note: Preferred MAC algorithm. No length-extension vulnerability. Use for all new deployments and ISO 8583 field 64.
    HMAC:
      tr31_key_usage: M7
      apc_enum_direct: HMAC_SHA256  # or HMAC_SHA224, HMAC_SHA384, HMAC_SHA512; HMAC (bare) also accepted
      security_note: Approved when used with SHA-256 or higher. Not commonly used for ISO 8583 MAC but valid for host-to-host integrity in non-scheme contexts.
    AS2805_MAC:
      tr31_key_usage: M0
      apc_enum_direct: AS2805_4_1
      security_note: Australian AS2805 network MAC. Regional requirement only.
  apc_operation_support:
    GenerateMac: supports all variants above (direct and DUKPT forms)
    VerifyMac: mirrors GenerateMac
  iso8583_mapping:
    field_64: Primary MAC — use M6 (CMAC) for new deployments; M3 accepted where network requires it
    field_128: Secondary MAC (extended bitmap)
status: active
```

## HSM Command Families

## Payment HSM Model

### Payment HSM

```yaml
id: concept.payment-hsm
entity_type: concept
canonical_name: Payment Hardware Security Module
aliases:
  - payment_hsm
  - payment HSM
summary: Specialized hardware security module used to protect payment keys and execute payment cryptographic operations under controlled security boundaries.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  primary_roles:
    - key_protection
    - key_generation
    - key_translation
    - PIN_processing
    - card_verification
    - EMV_cryptography
    - MAC_processing
status: active
```

### Issuing HSM

```yaml
id: concept.issuing-hsm
entity_type: concept
canonical_name: Issuing HSM
summary: Payment HSM role focused on card issuance, issuer-side PIN generation, issuer EMV key management, card verification value generation, and related provisioning functions.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  primary_use_cases:
    - pin_generation
    - pvv_generation
    - pin_offset_generation
    - emv_issuer_key_generation
    - card_verification_value_generation
relationships:
  - type: related_to
    target_id: concept.payment-hsm
status: active
```

### Acquiring HSM

```yaml
id: concept.acquiring-hsm
entity_type: concept
canonical_name: Acquiring HSM
summary: Payment HSM role focused on transaction processing between merchants, acquirers, switches, and networks, including PIN translation, PIN verification, CVV validation, and MAC processing.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  primary_use_cases:
    - pin_translation
    - pin_verification
    - cvv_validation
    - emv_validation
    - mac_generation
    - mac_verification
    - remote_key_loading
relationships:
  - type: related_to
    target_id: concept.payment-hsm
status: active
```

### HSM Security Domain Separation

```yaml
id: rule.payment-hsm-domain-separation
entity_type: constraint_rule
canonical_name: Payment HSM Domain Separation
summary: Payment issuing and payment acquiring responsibilities are often separated across different HSM deployments for security and compliance reasons.
domain:
  - hsm
  - key_management
constraints:
  - Issuing and acquiring functions should be modeled as distinct operational domains.
  - Key domains, users, and ceremonies often differ between issuing and acquiring environments.
status: active
```

### Local Master Key

```yaml
id: key-type.lmk
entity_type: key_type
canonical_name: Local Master Key
aliases:
  - LMK
summary: HSM-internal master protection key family used to protect keys under local storage and internal host-command workflows.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  scope: internal_to_hsm_or_cluster
status: active
```

### Master File Key

```yaml
id: key-type.mfk
entity_type: key_type
canonical_name: Master File Key
aliases:
  - MFK
summary: Major HSM protection key used as a foundational control point for securing device-resident key material and operational state.
domain:
  - hsm
  - key_management
  - cryptography
status: active
```

### Platform Master Key

```yaml
id: key-type.pmk
entity_type: key_type
canonical_name: Platform Master Key
aliases:
  - PMK
summary: HSM platform-level master key used in some product families for broader key-protection or platform-management contexts.
domain:
  - hsm
  - key_management
status: active
```

### Futurex Token Key

```yaml
id: key-type.ftk
entity_type: key_type
canonical_name: Token Master Key
aliases:
  - FTK
summary: Token-related master key concept used in token issuance or token security contexts in some payment HSM environments.
domain:
  - hsm
  - key_management
  - cryptography
status: active
```

### M of N Key Ceremony

```yaml
id: operation.m-of-n-key-ceremony
entity_type: operation
canonical_name: M of N Key Ceremony
aliases:
  - M_of_N
  - split knowledge ceremony
summary: Operational process in which a key or key component set is generated, loaded, or reconstructed using a threshold number of authorized key custodians.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  security_principles:
    - split_knowledge
    - dual_control
    - threshold_reconstruction
status: active
```

### Key Share

```yaml
id: artifact.key-share
entity_type: artifact
canonical_name: Key Share
aliases:
  - key component
summary: Fragment of a key used in split-knowledge loading or reconstruction ceremonies.
domain:
  - hsm
  - key_management
relationships:
  - type: related_to
    target_id: operation.m-of-n-key-ceremony
status: active
```

### Trusted Management Device

```yaml
id: concept.trusted-management-device
entity_type: concept
canonical_name: Trusted Management Device
aliases:
  - TMD
summary: Dedicated device or management path used to administer an HSM and participate in sensitive management or key-transfer workflows.
domain:
  - hsm
  - key_management
status: active
```

### Generic Payment HSM Operation Families

```yaml
id: concept.payment-hsm-operation-families
entity_type: concept
canonical_name: Payment HSM Operation Families
summary: Normalized families of operations exposed by payment HSMs regardless of vendor command syntax.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  families:
    - generate_key
    - import_key
    - export_key
    - translate_key
    - derive_key
    - generate_pin
    - verify_pin
    - translate_pin
    - generate_pvv
    - generate_pin_offset
    - generate_cvv
    - verify_cvv
    - generate_mac
    - verify_mac
    - emv_key_derivation
    - emv_certificate_generation
    - emv_validation
    - remote_key_loading
    - secure_messaging
status: active
```

### Vendor Command Crosswalk Record Shape

```yaml
id: concept.vendor-command-crosswalk
entity_type: concept
canonical_name: Vendor Command Crosswalk
summary: Mapping layer between canonical payment-HSM operations and vendor-specific host commands.
domain:
  - hsm
  - key_management
attributes:
  record_shape:
    vendor: string
    command_name: string
    command_code_request: string
    command_code_response: string
    canonical_operation_family: string
    key_types:
      - string
    notes:
      - string
status: active
```

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
    - Futurex
status: active
```

### Futurex Payment HSM

```yaml
id: concept.futurex-payment-hsm
entity_type: concept
canonical_name: Futurex Payment HSM
summary: Futurex payment-HSM family supporting issuing and acquiring payment use cases through Futurex-specific command and management interfaces.
domain:
  - hsm
  - key_management
  - cryptography
relationships:
  - type: related_to
    target_id: concept.payment-hsm
status: active
```

### Futurex Issuing Use Cases

```yaml
id: concept.futurex-issuing-use-cases
entity_type: concept
canonical_name: Futurex Issuing Use Cases
summary: Futurex-documented issuer-side use-case grouping for payment HSM integration.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  use_cases:
    - pin_and_offset_generation
    - emv_key_generation_and_derivation
    - mobile_payment_token_issuance
    - cvv_generation
relationships:
  - type: related_to
    target_id: concept.issuing-hsm
status: active
```

### Futurex Acquiring Use Cases

```yaml
id: concept.futurex-acquiring-use-cases
entity_type: concept
canonical_name: Futurex Acquiring Use Cases
summary: Futurex-documented acquirer-side use-case grouping for payment HSM integration.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  use_cases:
    - pin_translation_and_verification
    - emv_validation
    - mobile_payment_acceptance
    - cvv_validation
    - mac_generation_and_verification
    - remote_key_loading
    - atm_network
    - point_to_point_encryption
relationships:
  - type: related_to
    target_id: concept.acquiring-hsm
status: active
```

### Generic Vendor Command Crosswalk Examples

```yaml
id: command-crosswalk.generic-generate-bdk
entity_type: command
canonical_name: Generate Base Derivation Key
summary: Canonical operation for generating a base derivation key within a payment HSM.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  canonical_operation_family: generate_key
  key_types:
    - BDK
  vendor_examples:
    - vendor: Thales
      command_name: Generate a BDK
      command_code_request: BI
      command_code_response: BJ
    - vendor: Futurex
      command_name: vendor_specific_not_normalized_here
      command_code_request: null
      command_code_response: null
status: active
```

```yaml
id: command-crosswalk.generic-generate-pvv
entity_type: command
canonical_name: Generate Visa PIN Verification Value
summary: Canonical operation for producing a PVV from issuer-side PIN verification inputs.
domain:
  - hsm
  - key_management
  - pin_processing
attributes:
  canonical_operation_family: generate_pvv
  key_types:
    - PVK
  vendor_examples:
    - vendor: Thales
      command_name: Generate Visa PIN Verification Value
      command_code_request: DG
      command_code_response: null
    - vendor: Futurex
      command_name: Visa PIN Verification Value workflow
      command_code_request: null
      command_code_response: null
status: active
```

```yaml
id: command-crosswalk.generic-generate-pin-offset
entity_type: command
canonical_name: Generate IBM 3624 PIN Offset
summary: Canonical operation for generating an IBM 3624 PIN offset from validation data and issuer PIN controls.
domain:
  - hsm
  - key_management
  - pin_processing
attributes:
  canonical_operation_family: generate_pin_offset
  key_types:
    - PVK
  vendor_examples:
    - vendor: Thales
      command_name: Generate IBM 3624 PIN Offset
      command_code_request: BK
      command_code_response: BL
    - vendor: Futurex
      command_name: GOFF
      command_code_request: GOFF
      command_code_response: null
status: active
```

```yaml
id: command-crosswalk.generic-derive-dukpt-ipek
entity_type: command
canonical_name: Derive DUKPT Initial Key
summary: Canonical operation for deriving the device initialization key used by DUKPT-capable devices.
domain:
  - hsm
  - key_management
  - cryptography
attributes:
  canonical_operation_family: derive_key
  key_types:
    - BDK
    - IPEK
  vendor_examples:
    - vendor: Thales
      command_name: Derive DUKPT Initial PIN Encryption Key
      command_code_request: 38C
      command_code_response: null
    - vendor: Futurex
      command_name: vendor_specific_not_normalized_here
      command_code_request: null
      command_code_response: null
status: active
```

```yaml
id: command-crosswalk.generic-generate-emv-mac
entity_type: command
canonical_name: Generate EMV Message Authentication Code
summary: Canonical operation for generating a MAC used in EMV data protection or secure messaging contexts.
domain:
  - hsm
  - key_management
  - cryptography
  - emv
attributes:
  canonical_operation_family: generate_mac
  vendor_examples:
    - vendor: Thales
      command_name: EMV Message Authentication Code Generation
      command_code_request: 352
      command_code_response: null
    - vendor: Futurex
      command_name: EMVM
      command_code_request: EMVM
      command_code_response: null
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

### CyberChef Payment Operations Fork

```yaml
id: tool.cyberchef-payment-fork
entity_type: tool_capability
canonical_name: CyberChef Payment Operations Fork
aliases:
  - cyberchef.jacobmarks.com
summary: >
  A fork of the GCHQ CyberChef web tool extended with a Payment module containing 31 payment-domain
  operations. Useful for test vector generation, algorithm cross-verification, and recipe chaining
  in the browser. Hosted at https://cyberchef.jacobmarks.com/.
domain:
  - testing
  - cryptography
  - pin_processing
  - card_validation
  - emv
  - key_management
attributes:
  payment_operations_covered:
    - DUKPT TDES and AES key derivation (ANSI X9.24-1, X9.24-3)
    - ISO PIN block build and parse (Format 0, 1, 3)
    - VISA PVV generate and verify
    - IBM 3624 PIN offset generate and verify
    - CVV/CVV2/iCVV generate and verify
    - EMV ARQC/ARPC generate and verify (AES-CMAC, supplied-key)
    - EMV MAC generate and verify (ISO 9797-1 Alg 3, padding Method 2)
    - ISO 9797-1 MAC Alg 1 and Alg 3 generate and verify
    - AS2805 MAC, HMAC, AES-CMAC
    - Payment data encrypt/decrypt/re-encrypt (AES, TDES, DUKPT variants)
    - TR-31 key block parse (header inspection only — no decryption)
    - TR-34 B9 envelope inspection
    - Payment KCV calculate
    - Test PAN generate
    - Translate PIN block (Format 0/1/3 ↔ Format 0/1/3, clear-key)
  validation_posture: >
    Operations backed by established primitives (AES-CMAC, HMAC, CMAC) are high-confidence.
    AES DUKPT key derivation is verified against all five ANSI X9.24-3-2017 normative test-vector
    suites (artifact.ansi-x9-24-3-test-vectors). Other payment-specific operations (CVV, PVV,
    ISO 9797-1) are partially verified — cross-check against payShield or APC for production use.
  recipe_chaining: >
    Operations output as hex or short scalar values that flow into the next operation's input.
    Generate ops return the short artifact (ARQC, PVV, PIN offset) with outputJson=false for
    chaining into Verify ops.
  not_covered:
    - TR-31 key block decryption (parsing only — issue #13 in the fork repo)
    - TR-31 key block decryption (parsing only — issue #13 in the fork repo)
    - Issuer card personalization, IMK/CMK derivation (out of scope)
relationships:
  - type: related_to
    target_id: rule.cvv-family-contexts
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### AWS Payment Cryptography HSM Proxy

```yaml
id: tool.apc-hsm-proxy
entity_type: tool_capability
canonical_name: AWS Payment Cryptography HSM Proxy
aliases:
  - apc-proxy
  - apc-hsm-proxy
summary: >
  A Rust TCP proxy (J8k3/aws-payment-cryptography-hsm-proxy) that sits between HSM-dependent
  payment applications and AWS Payment Cryptography. It speaks the wire protocol the application
  already sends — Thales payShield 10K host commands or Futurex Excrypt Enterprise SSP v.2 —
  and translates them to APC API calls, without changing the application. Use when application
  refactoring is not on the table; if the application can be changed, call the APC SDK directly.
domain:
  - hsm_migration
  - pin_processing
  - card_validation
  - key_management
attributes:
  supported_protocols:
    - thales_payshield: >
        2-byte length prefix + 2-byte command code framing. Handlers: CA/CC/CI/G0 (PIN translate),
        C2/C4/M6/M8 (MAC generate/verify), CW/CY (CVV generate/verify), B2 (echo/heartbeat),
        MA/MC/ME (legacy TAK MAC generate/verify/translate, ISO 9797 Algorithm 1),
        CK/CM (DUKPT IBM3624/Visa PVV PIN verify), CO/CQ (DUKPT Diebold/Encrypted PIN — stub 68).
    - futurex_excrypt: >
        [AOCCCC;param;param;] bracket-delimited framing. Handlers: ECHO (heartbeat), TPIN (PIN translate).
  workflow:
    phase_1_discovery: >
      Run proxy in passthrough mode against the real HSM. Commands are forwarded and logged to
      discovery.jsonl (one record per unique command code, sensitive fields redacted). Feed the log
      to the apc-agent hsm_analyze_discovery_log tool, which maps each command to its APC operation,
      key type, and handler file path. AI writes the Rust handler code.
    phase_2_translation: >
      Disable passthrough. key_mappings in proxy.yaml resolves the application's key identifiers
      (LMK blobs, TR-31 values, labels) to APC ARNs or aliases before making API calls. Commands
      without a registered handler return error 68 (unsupported).
  status_note: >
    Not tested against a real HSM client application. Parsers are built from specification and
    reference documentation. Known gaps are documented in the README Known Risks section.
  known_risks:
    - APC latency 20-100ms vs sub-millisecond hardware HSM — tight socket timeouts will fail
    - Thales length field variant — some payShield versions count payload only, not header+payload
    - Futurex error codes map to payShield-style codes (non-standard BB field values)
    - TLS cipher compat — rustls requires TLS 1.2 minimum; older HSM client SDKs may not support it
    - Discovery passthrough is single-chunk per command; stateful/multi-read sequences won't work
  extension_point: >
    Add src/handlers/<vendor>/<command>.rs implementing the Handler trait; register in
    src/handlers/mod.rs. The Futurex parse_params() helper splits Excrypt payloads into a
    HashMap<[u8;2], Vec<u8>>. Wrap key blocks and PIN blocks in Zeroizing<Vec<u8>>.
relationships:
  - type: companion_to
    target_id: tool.apc-agent
    notes: >
      hsm_analyze_discovery_log in apc-agent is the intended Phase 1 analysis tool — it maps
      discovery.jsonl entries to APC operations and generates handler scaffolding.
  - type: related_to
    target_id: tool.cyberchef-payment-fork
    notes: CyberChef fork can be used to verify handler output (CVV, MAC, PIN) at the operation level.
status: active
```

## APC SDK Implementation Notes

### verify_pin_data Type Naming Trap

```yaml
id: rule.apc-verify-pin-data-types
entity_type: constraint_rule
canonical_name: APC verify_pin_data uses different types than generate_pin_data
summary: >
  The APC Rust SDK (aws-sdk-paymentcryptographydata v1.x) uses DIFFERENT struct types for
  PIN verification vs PIN generation. Using the wrong type causes silent compile errors or
  runtime failures. This is the most common mistake when implementing verify_pin_data handlers.
domain:
  - pin_processing
  - hsm_migration
attributes:
  verified_against: aws-sdk-paymentcryptographydata 1.105.0
  verify_pin_data_types:
    ibm3624_verification: Ibm3624PinVerification
    ibm3624_verification_fields:
      - decimalization_table: String (required)
      - pin_validation_data_pad_character: String (required, use "F" for IBM 3624 standard)
      - pin_validation_data: String (required, 12 alphanumeric chars from payShield CK)
      - pin_offset: String (required, 12H F-padded IBM offset from payShield CK)
    visa_verification: VisaPinVerification
    visa_verification_fields:
      - pin_verification_key_index: i32 (required, PVKI from payShield CM)
      - verification_value: String (required, PVV 4N from payShield CM)
    wrong_types_for_verify:
      - Ibm3624PinOffset: "for generate_pin_data only — NOT verify_pin_data"
      - VisaPinVerificationValue: "for generate_pin_data only — NOT verify_pin_data"
    pin_verification_attributes_enum:
      ibm3624: PinVerificationAttributes::Ibm3624Pin(Ibm3624PinVerification)
      visa: PinVerificationAttributes::VisaPin(VisaPinVerification)
  dukpt_key_placement:
    bdk_arn: "goes in encryption_key_identifier on the OUTER verify_pin_data() call"
    pvk_arn: "goes in verification_key_identifier on the OUTER verify_pin_data() call"
    pin_block: "goes in encrypted_pin_block on the OUTER verify_pin_data() call"
    dukpt_attributes_fields:
      - key_serial_number: String (KSN hex — required)
      - dukpt_derivation_type: DukptDerivationType (required, use Tdes2Key for original DUKPT)
    dukpt_attributes_does_NOT_have:
      - key_identifier: "BDK ARN does NOT go inside DukptAttributes — it goes in encryption_key_identifier"
      - dukpt_key_variant: "no such field — remove if copied from older SDK examples"
constraints:
  - "Ibm3624PinVerification has no encrypted_pin_block field — pin block is at the outer call level"
  - "VisaPinVerification has no encrypted_pin_block field — pin block is at the outer call level"
  - "DukptAttributes has exactly two required fields: key_serial_number and dukpt_derivation_type"
  - "BDK ARN is passed via encryption_key_identifier (outer field), NOT inside DukptAttributes"
status: active
```

## Cross-Cutting Constraint Rules

### DUKPT Versus Encryption Rule

```yaml
id: rule.dukpt-is-key-management
entity_type: constraint_rule
canonical_name: DUKPT Is Key Management, Not Encryption
summary: DUKPT should be modeled separately from the ciphers and MAC algorithms used with the derived keys.
domain:
  - key_management
  - cryptography
constraints:
  - DUKPT governs derivation and key lifecycle, not the ciphertext format by itself.
  - Derived keys may be used for PIN encryption, data encryption, or MAC generation depending on the implementation.
status: active
```

### AES DUKPT Derivation Data Structure (X9.24-3)

```yaml
id: rule.aes-dukpt-derivation-data-structure
entity_type: constraint_rule
canonical_name: AES DUKPT Derivation Data Structure (ANSI X9.24-3)
summary: >
  AES DUKPT uses a 16-byte derivation data block as the AES-CMAC input for every key
  derivation step. IK derivation and working-key derivation use different layouts. Mixing
  them produces silently wrong keys; the only reliable check is running against the
  normative X9.24-3-2017 test vectors.
domain:
  - key_management
  - cryptography
attributes:
  cmac_algorithm: AES-CMAC (RFC 4493)
  derivation_data_length: 16 bytes
  common_header_bytes_0_7:
    byte_0: version = 0x01
    byte_1: key_class = 0x01
    bytes_2_3: key_usage (purpose-specific, see below)
    bytes_4_5: algorithm = 0x0002 (AES-128)
    bytes_6_7: key_length = 0x0080 (128 bits)
  ik_derivation_data_bytes_8_15:
    layout: full 8-byte IKI (device identifier portion with counter all-zeros)
    key_usage: 0x8001
    note: no counter field; full IKI fills bytes 8-15
  working_key_derivation_data_bytes_8_15:
    bytes_8_11: last 4 bytes of IKI only (NOT the full 8-byte IKI)
    bytes_12_15: full 32-bit transaction counter (NOT masked to 21 bits)
  key_usage_codes:
    IK_derivation: 0x8001
    intermediate_node: 0x0000
    PIN_encryption: 0x1000
    MAC_generation: 0x2000
    MAC_verification: 0x2001
    MAC_both_ways: 0x2002
    data_encryption: 0x3000
    data_decryption: 0x3001
    data_both_ways: 0x3002
    KEK: 0x0002
  common_implementation_mistakes:
    - Using KEY_USAGE 0x8000 for IK derivation instead of 0x8001
    - Using version byte 0x00 instead of 0x01
    - Using full 8-byte IKI in working-key derivation data (correct only for IK derivation)
    - Using only the last 4 bytes of IKI in IK derivation data (correct only for working keys)
    - Masking the counter to 21 bits before embedding in derivation data (embed full 32-bit value)
relationships:
  - type: related_to
    target_id: algorithm.dukpt
  - type: related_to
    target_id: artifact.ansi-x9-24-3-test-vectors
constraints:
  - All AES DUKPT derivation steps use AES-CMAC, not AES-CBC or AES-ECB
  - Version byte 0x01 is mandatory; 0x00 produces silently wrong keys
  - IK derivation KEY_USAGE is 0x8001; working key usages start at 0x0000/0x1000
  - Run against normative X9.24-3-2017 test vectors (see artifact.ansi-x9-24-3-test-vectors) before declaring an AES DUKPT implementation correct
status: active
```

### PCI Data Classification Rule

```yaml
id: rule.pci-data-classification
entity_type: constraint_rule
canonical_name: PCI Data Classification
summary: Payment data should be classified into cardholder data and sensitive authentication data because handling rules differ materially.
domain:
  - card_data
  - pin_processing
  - cryptography
constraints:
  - Cardholder data includes PAN and may include cardholder name, expiration date, and service code.
  - Sensitive authentication data includes full track data, card verification codes, and PIN or PIN-block data.
  - Sensitive authentication data requires stricter storage controls than ordinary cardholder data.
status: active
```

### PAN Display Rule

```yaml
id: rule.pan-display-protection
entity_type: constraint_rule
canonical_name: PAN Display Protection
summary: Full PAN should not be unnecessarily displayed, printed, or stored in clear form.
domain:
  - card_data
  - cryptography
constraints:
  - PAN truncation is a standard protective pattern for display and receipts.
  - Tokenization and format-preserving encryption are common mitigation patterns for operational systems.
status: active
```

### DUKPT Security Boundary Rule

```yaml
id: rule.dukpt-security-boundary
entity_type: constraint_rule
canonical_name: DUKPT Security Boundary
summary: In DUKPT, compromise scope depends heavily on which level of key material is exposed.
domain:
  - key_management
  - cryptography
constraints:
  - Exposure of a transaction key should not reveal past or future transaction keys.
  - Exposure of one device state should not implicitly compromise other devices in the same fleet.
  - Exposure of the base derivation key can compromise all devices and transactions in that derivation domain.
status: active
```

### DUKPT KSN Rule

```yaml
id: rule.dukpt-ksn-usage
entity_type: constraint_rule
canonical_name: DUKPT KSN Usage
summary: DUKPT decryption or verification requires both the protected data and the associated key serial number.
domain:
  - key_management
  - cryptography
  - pin_processing
constraints:
  - The KSN identifies the device context and transaction counter position used for derivation.
  - Receiver-side systems use the KSN counter position and device context to regenerate the same transaction key without receiving the derived key from the device.
status: active
```

### DUKPT Transaction Lifecycle Rule

```yaml
id: rule.dukpt-transaction-lifecycle
entity_type: constraint_rule
canonical_name: DUKPT Transaction Lifecycle
summary: DUKPT devices consume derivation state as transactions occur and do not reuse one-time transaction keys.
domain:
  - key_management
  - cryptography
constraints:
  - A device retrieves key material from its future-key set for a transaction.
  - The device transaction counter advances after each transaction and determines which transaction key is selected.
  - The receiver derives the same transaction key by interpreting the counter position carried in the KSN.
  - The consumed key material is invalidated and new future keys may be generated.
status: active
```

### ISO 9564 PIN-Protection Rule

```yaml
id: rule.iso9564-pin-protection
entity_type: constraint_rule
canonical_name: ISO 9564 PIN Protection
summary: PINs should be encoded into PIN blocks and encrypted with approved algorithms when transmitted through interoperable financial systems.
domain:
  - pin_processing
  - cryptography
constraints:
  - Common approved encryption families include TDES, RSA, and AES.
  - PIN and associated card material must be handled under strict separation and protection controls.
status: active
```

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
summary: >
  Card verification values are context-specific. Service code is a cryptographic input to the
  CVV algorithm — not metadata. Using the wrong service code for a CVV family member produces
  a cryptographically incorrect value that will always fail host verification.
domain:
  - card_validation
constraints:
  - CVV1 is associated with stripe or card-present contexts.
  - CVV2 is associated with card-not-present contexts.
  - iCVV is associated with chip contexts.
  - dCVV and dCVC are dynamic and transaction-linked or context-linked.
  - Printed card security codes should not be treated as equivalent to EMV-generated dynamic values.
service_code_as_cryptographic_input:
  explanation: >
    The CVV algorithm takes PAN + expiry date + service code as inputs. The service code is not
    a label applied after the fact — it is fed into the 3DES computation. Changing the service
    code produces a different CVV value. Verification with a mismatched service code will always
    fail, even with the correct key.
  scheme_mandated_values:
    CVV1: >
      Use the actual service code present in Track 2 data (commonly "201" for international
      magnetic-stripe cards). The caller must pass the real Track 2 service code, not a default.
    CVV2: >
      Service code "000" is the scheme-mandated input for CVV2. APC's CardVerificationValue2
      struct does not accept a ServiceCode parameter — the value 000 is applied implicitly by
      the service. Do not attempt to pass a service code for CVV2 generation or verification.
    iCVV: >
      Service code "999" is the scheme-mandated input for iCVV. This value is specific to chip
      card contexts and is intentionally different from any valid magnetic-stripe service code.
  anti_cloning_property: >
    The iCVV service code mandate (999) is a deliberate anti-fraud mechanism. Even if an
    attacker skims the iCVV value from a chip transaction, it cannot be replayed on a cloned
    magnetic stripe: the stripe would carry a real service code (e.g., 201), but the iCVV was
    generated with service code 999. Host verification using the actual stripe service code
    will fail, detecting the fraud.
  apc_api_note:
    CardVerificationValue1: Requires ServiceCode field explicitly. Pass the actual Track 2 service code for CVV1; pass "999" for iCVV generation using this struct.
    CardVerificationValue2: Does not accept ServiceCode. The 000 substitution is applied by APC internally.
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

### VISA PVV Two-Pass Decimalization Rule

```yaml
id: rule.pvv-decimalization
entity_type: constraint_rule
canonical_name: VISA PVV Two-Pass Decimalization
summary: >
  The VISA PVV selection algorithm uses a two-pass decimalization. An incorrect single-pass
  implementation will produce wrong PVV values whenever hex letters appear before decimal digits
  in the TDES-encrypted output.
domain:
  - pin_processing
  - cryptography
constraints:
  - Pass 1: scan the 16-character TDES-encrypted PVV input left to right; collect only decimal digits
    (0-9). Stop when 4 digits are found.
  - Pass 2: only if pass 1 produced fewer than 4 digits — rescan the same 16 characters, mapping
    each hex letter using A=0, B=1, C=2, D=3, E=4, F=5. Append mapped digits until 4 total.
  - A single-pass that immediately maps hex letters will produce incorrect PVV whenever a hex letter
    appears before the fourth decimal digit in the output.
  - The CVV family decimalization (CVV/CVV2/iCVV) uses the same two-pass approach; implementations
    should be consistent.
  - APC VerifyPinData handles this correctly on the HSM side; a mismatch between client-computed PVV
    and APC-verified PVV is often caused by single-pass vs two-pass confusion.
relationships:
  - type: related_to
    target_id: artifact.pvv
  - type: related_to
    target_id: algorithm.visa-pin
  - type: related_to
    target_id: rule.cvv-family-contexts
status: active
```

### ARQC Preimage Assembly Rule

```yaml
id: rule.arqc-preimage-assembly
entity_type: constraint_rule
canonical_name: ARQC Preimage Assembly
summary: >
  The ARQC is computed over an assembled preimage, not directly over individual EMV tags.
  The preimage byte layout is scheme-specific; using the wrong layout produces a
  cryptogram that cannot be verified even with the correct session key.
domain:
  - emv
  - cryptography
constraints:
  - The ARQC preimage is constructed by concatenating EMV transaction data in a fixed order
    defined by the card scheme (Visa, Mastercard, etc.) and the issuer's personalization profile.
  - Typical elements included (in order): amount authorized (tag 9F02), amount other (9F03),
    terminal country code (9F1A), terminal verification results (95), transaction currency code
    (5F2A), transaction date (9A), transaction type (9C), unpredictable number (9F37),
    application interchange profile (82), application transaction counter (9F36),
    issuer application data / card verification results (9F10 sub-fields as applicable).
  - For EMV MAC and ARPC, the preimage is the already-assembled bytes as hex; the
    cryptogram operation itself is AES-CMAC(session_key, preimage_bytes)[0:8].
  - APC VerifyAuthRequestCryptogram takes the transaction data (CDOL-R1 or full chip data TLV)
    and key ARN; it assembles the preimage internally per EMV Book 2 Annex A1.
  - When using a software tool (e.g., CyberChef EMV Verify ARQC), the preimage must be
    assembled externally before passing it to the operation; the tool does not parse TLV.
  - The session key is typically derived from the issuer master key (E0 type) using ATC-based
    EMV key derivation (Option A or Common Session Key derivation) applied before computing the ARQC.
  - ARPC input = ARQC || ARC (Authorization Response Code, 2 bytes). Both are then passed to
    AES-CMAC with the issuer session key to produce the ARPC.
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: artifact.arpc
  - type: related_to
    target_id: algorithm.emv-key-derivation
  - type: related_to
    target_id: tool.cyberchef-payment-fork
status: active
```

### ISO 9797-1 Payment Industry Interpretation Rule

```yaml
id: rule.iso9797-payment-interpretation
entity_type: constraint_rule
canonical_name: ISO 9797-1 MAC Payment Industry Interpretation
summary: >
  The payment industry uses the labels "Algorithm 1" and "Algorithm 3" differently from
  the pure ISO 9797-1 definitions. Understanding the difference prevents key or padding
  mismatches during implementation.
domain:
  - cryptography
constraints:
  - "Pure ISO 9797-1 Algorithm 1: straightforward CBC-MAC using a single algorithm (DES, TDES, or AES) for all blocks."
  - "Payment industry Algorithm 1 (as used in EMV and acquirer MAC contexts): DES CBC-MAC using the left half of the TDES key for all blocks except the last, then a TDES output transform (E-K1, D-K2, E-K3) on the final block only."
  - "Payment industry Algorithm 3 (Retail MAC, ANSI X9.19): DES CBC-MAC with K1 (left 8 bytes) for all blocks, then decrypt with K2 (right 8 bytes), then re-encrypt with K3 (= K1 for 2-key, or third 8-byte segment for 3-key)."
  - "The difference between Algorithm 1 and Algorithm 3 in the payment context is the final output transform: TDES-wrap (Alg 1) vs. decrypt-then-encrypt (Alg 3)."
  - "ISO 9797-1 Padding Method 2 (80-then-zeros) is standard for EMV MAC. Padding Method 1 (zero-padding) is used in some acquirer host MAC contexts."
  - "APC MAC operation enums: ISO9797_ALGORITHM1 (M1 key), ISO9797_ALGORITHM3 (M3 key), CMAC (M6 key)."
relationships:
  - type: related_to
    target_id: algorithm.mac-iso9797
  - type: related_to
    target_id: rule.cvv-family-contexts
status: active
```

## EMV Security Model

### EMV Transaction Flow

```yaml
id: operation.emv-transaction-flow
entity_type: operation
canonical_name: EMV Transaction Flow
summary: Canonical sequence of terminal and card processing steps used during an EMV transaction.
domain:
  - emv
  - cryptography
attributes:
  typical_steps:
    - application_selection
    - initiate_application_processing
    - read_application_data
    - processing_restrictions
    - offline_data_authentication
    - cardholder_verification
    - terminal_risk_management
    - terminal_action_analysis
    - card_action_analysis
    - online_authorization_if_required
    - issuer_script_processing
status: active
```

### Offline Data Authentication

```yaml
id: operation.emv-offline-data-authentication
entity_type: operation
canonical_name: EMV Offline Data Authentication
aliases:
  - ODA
summary: Card-authentication stage in which the terminal validates card authenticity using public-key mechanisms before or without host involvement.
domain:
  - emv
  - cryptography
attributes:
  methods:
    - SDA
    - DDA
    - CDA
status: active
```

### SDA

```yaml
id: operation.emv-sda
entity_type: operation
canonical_name: Static Data Authentication
aliases:
  - SDA
summary: EMV offline data authentication method that validates issuer-signed card data but does not by itself prevent card cloning.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: operation.emv-offline-data-authentication
status: active
```

### DDA

```yaml
id: operation.emv-dda
entity_type: operation
canonical_name: Dynamic Data Authentication
aliases:
  - DDA
summary: EMV offline data authentication method using card-generated dynamic cryptographic proof to resist cloning.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: operation.emv-offline-data-authentication
status: active
```

### CDA

```yaml
id: operation.emv-cda
entity_type: operation
canonical_name: Combined Data Authentication
aliases:
  - CDA
summary: EMV authentication method combining dynamic authentication with application cryptogram generation to provide stronger transaction assurance.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: operation.emv-offline-data-authentication
  - type: related_to
    target_id: artifact.arqc
status: active
```

### Cardholder Verification Method

```yaml
id: concept.cvm
entity_type: concept
canonical_name: Cardholder Verification Method
aliases:
  - CVM
summary: Method used in EMV and payment flows to assess whether the person presenting the card is the legitimate cardholder.
domain:
  - emv
  - pin_processing
  - card_validation
attributes:
  common_methods:
    - signature
    - offline_plaintext_pin
    - offline_enciphered_pin
    - online_pin
    - no_cvm
relationships:
  - type: related_to
    target_id: data_element.emv-tag-8e
status: active
```

### Offline Plaintext PIN

```yaml
id: operation.offline-plaintext-pin
entity_type: operation
canonical_name: Offline Plaintext PIN Verification
summary: Cardholder verification method in which the terminal presents the PIN to the card for local verification without issuer-host involvement.
domain:
  - emv
  - pin_processing
  - cryptography
relationships:
  - type: related_to
    target_id: concept.cvm
status: active
```

### EMV Issuer Script

```yaml
id: operation.emv-issuer-script
entity_type: operation
canonical_name: EMV Issuer Script
summary: Issuer-generated command sequence delivered through EMV messaging to instruct the card to perform post-authorization actions such as parameter changes or PIN-related updates.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: key-type.imk
status: active
```

### Offline PIN Update

```yaml
id: operation.offline-pin-update
entity_type: operation
canonical_name: Offline PIN Update
summary: Chip-card PIN change flow typically carried in an EMV issuer script and protected using issuer secure-messaging keys together with transaction context.
domain:
  - emv
  - pin_processing
  - cryptography
attributes:
  common_context_elements:
    - atc
    - arqc
    - issuer_script_mac
relationships:
  - type: related_to
    target_id: operation.emv-issuer-script
  - type: related_to
    target_id: operation.offline-enciphered-pin
constraints:
  - Offline PIN update is an issuer-side chip-management function rather than a normal acquirer PIN-translation flow.
status: active
```

### Offline Enciphered PIN

```yaml
id: operation.offline-enciphered-pin
entity_type: operation
canonical_name: Offline Enciphered PIN Verification
summary: Cardholder verification method in which the PIN is enciphered for card-side verification during offline EMV processing.
domain:
  - emv
  - pin_processing
  - cryptography
relationships:
  - type: related_to
    target_id: concept.cvm
status: active
```

### Online PIN

```yaml
id: operation.online-pin
entity_type: operation
canonical_name: Online PIN Verification
summary: Cardholder verification method in which the PIN is protected and verified by issuer-side or host-side systems.
domain:
  - emv
  - pin_processing
  - cryptography
relationships:
  - type: related_to
    target_id: concept.cvm
  - type: related_to
    target_id: artifact.encrypted-pin-block
status: active
```

### No CVM

```yaml
id: operation.no-cvm
entity_type: operation
canonical_name: No Cardholder Verification Method
aliases:
  - no_cvm
summary: Transaction path in which no explicit cardholder verification step is required by the card, terminal, or risk rules.
domain:
  - emv
  - card_validation
relationships:
  - type: related_to
    target_id: concept.cvm
status: active
```

### Terminal Risk Management

```yaml
id: operation.emv-terminal-risk-management
entity_type: operation
canonical_name: EMV Terminal Risk Management
summary: Terminal-side decision stage that evaluates whether a transaction should proceed offline, go online, or be declined based on local risk checks.
domain:
  - emv
  - cryptography
  - iso8583
attributes:
  common_checks:
    - offline_ceiling_limit
    - random_online_selection
    - hot_card_list
relationships:
  - type: related_to
    target_id: data_element.emv-tag-95
status: active
```

### Terminal Action Analysis

```yaml
id: operation.emv-terminal-action-analysis
entity_type: operation
canonical_name: EMV Terminal Action Analysis
summary: EMV decision stage using terminal and issuer action codes together with prior results to choose offline approval, online authorization, or offline decline.
domain:
  - emv
  - cryptography
relationships:
  - type: related_to
    target_id: data_element.emv-tag-95
status: active
```

### EMV Implementation Rule

```yaml
id: rule.emv-common-vs-scheme-specific
entity_type: constraint_rule
canonical_name: EMV Common Versus Scheme-Specific Layers
summary: EMV includes both common cross-scheme specifications and scheme-specific implementations or programs.
domain:
  - emv
constraints:
  - Common EMV concepts should be modeled separately from network-specific implementations.
  - Certification and brand overlays should be represented as scheme variants rather than replacing canonical EMV records.
status: active
```

## AWS Payment Cryptography — APC-Specific Reference

### APC Key Lifecycle

```yaml
id: concept.apc-key-lifecycle
entity_type: concept
canonical_name: AWS Payment Cryptography Key Lifecycle
aliases:
  - APC key states
summary: >
  APC keys pass through defined lifecycle states. Key attributes are immutable
  post-creation. Keys are rotated via alias reassignment rather than in-place mutation.
domain:
  - key_management
  - cryptography
attributes:
  key_states:
    CREATE_COMPLETE: active and usable
    DELETE_PENDING: scheduled for deletion; still usable during retention window
    DELETE_COMPLETE: permanently deleted; unrecoverable
  key_origin:
    AWS_PAYMENT_CRYPTOGRAPHY: generated inside APC HSM
    EXTERNAL: imported via TR-31, TR-34, ECDH, or RSA
  immutable_attributes: [algorithm, key_length, key_usage, key_class, key_origin]
  mutable_attributes: [effective_date, expiry_date, tags, deletion_window]
  rotation_pattern: >
    Create new key → update alias ARN to new key → disable/delete old key.
    Consuming code references the alias and requires no updates.
  ipek_ik_note: >
    IPEK/IK keys derived for export are computed on demand and not stored by APC.
    Each export re-derives from the parent BDK.
constraints:
  - Key attributes (algorithm, usage) cannot be changed after creation or import
  - Replica Region Keys (RRK) are read-only; all mutations target the Primary Region Key (PRK)
status: active
```

### APC Multi-Region Keys

```yaml
id: concept.apc-multi-region-keys
entity_type: concept
canonical_name: AWS Payment Cryptography Multi-Region Keys
aliases:
  - PRK
  - RRK
summary: >
  APC keys can be replicated across AWS regions. The original is the Primary Region Key
  (PRK); replicated copies are Replica Region Keys (RRK). Shared key material, separate
  region-specific ARNs.
domain:
  - key_management
attributes:
  PRK: original key; all lifecycle operations performed here
  RRK: read-only regional copy; supports cryptographic operations but not metadata changes
  use_cases: [disaster_recovery, multi-region active-active payment processing]
constraints:
  - Replication, attribute changes, and deletion must be performed on the PRK
status: active
```

### APC Dynamic Keys (MPoC / Inline Key Transport)

```yaml
id: concept.apc-dynamic-keys
entity_type: concept
canonical_name: AWS Payment Cryptography Dynamic Keys
aliases:
  - APC inline key
  - MPoC keys
  - APC wrapped key transport
summary: >
  APC data-plane operations accept short-lived TR-31 wrapped key blocks passed inline
  instead of requiring keys to be pre-imported. Designed for MPoC (Mobile Point of
  Capture) and softPOS deployments where per-transaction key provisioning is common.
domain:
  - key_management
  - pin_processing
  - cryptography
attributes:
  supported_operations: [EncryptData, DecryptData, ReEncryptData, TranslatePinData]
  wrapping_kek: must be pre-imported to APC; usage TR31_K0 or TR31_K1
  pin_key_requirements:
    key_usage: P0 (PIN encryption)
    mode_of_use: B (both) or D (decrypt-only)
  data_key_requirements:
    key_usage: D0 (data encryption)
    mode_of_use: B or D
  lifecycle: dynamic key is not persisted in APC key store; exists only for the operation
relationships:
  - type: uses
    target_id: key-block.tr31
  - type: related_to
    target_id: key-type.kek
constraints:
  - Wrapping KEK must be pre-imported; only the TR-31 payload is inline
  - Key usage and mode in the TR-31 header are enforced by APC
status: active
```

### KBPK — Key Block Protection Key

```yaml
id: key_type.kbpk
entity_type: key_type
canonical_name: Key Block Protection Key (KBPK)
aliases:
  - KBPK
  - TR31_K1_KEY_BLOCK_PROTECTION_KEY
  - TR31_K0_KEY_ENCRYPTION_KEY
summary: >
  Key used to protect (wrap) other keys in a TR-31 key block. Two TR-31 usage codes
  apply: K1 (preferred per X9.143) and K0 (legacy, retained for compatibility).
  APC accepts both interchangeably.
domain:
  - key_management
  - cryptography
attributes:
  preferred_usage: TR31_K1_KEY_BLOCK_PROTECTION_KEY
  legacy_usage: TR31_K0_KEY_ENCRYPTION_KEY
  algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
  apc_note: K0 and K1 are functionally interchangeable in APC; K1 preferred per X9.143
  tr31_version:
    TDES_KBPK: version B
    AES_KBPK: version D
relationships:
  - type: related_to
    target_id: key-block.tr31
  - type: related_to
    target_id: key-type.kek
constraints:
  - Wrapping key must be at least as strong as the wrapped key (APC enforces this)
status: active
```

### APC ECDH Key Agreement — Operational Specifics

```yaml
id: concept.apc-ecdh-key-agreement
entity_type: concept
canonical_name: APC ECDH Key Agreement Operational Details
summary: >
  APC implements NIST SP800-56A ECDH for importing and exporting symmetric keys.
  An ECC key pair with usage K3 is required; DeriveKeyUsage is fixed at key creation.
domain:
  - key_management
  - cryptography
attributes:
  required_key_usage: TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT
  mode_of_use: DeriveKey (only valid mode for K3)
  derive_key_usage_fixed_at_creation: true
  supported_curves: [NIST_P256, NIST_P384, NIST_P521]
  supported_kdf: NIST_SP800_56A with SHA_256 / SHA_384 / SHA_512
  party_roles:
    import: APC is Party V (Responder); caller provides ephemeral public key
    export: APC is Party U (Initiator); APC provides ephemeral public key
  certificate_chain_rule: >
    P-384 CA can only issue P-384 or P-521 leaf certs.
    Weaker-to-stronger issuance is not permitted.
  aes256_note: ECDH is the ONLY path for AES-256 key transport; RSA wrap does not support AES-256
relationships:
  - type: related_to
    target_id: algorithm.ecdh
  - type: related_to
    target_id: rule.apc-key-wrapping-strength
constraints:
  - A given K3 key pair can only derive one type of output key (DeriveKeyUsage fixed at creation)
  - Cannot reuse an ECC key pair for a different DeriveKeyUsage purpose
status: active
```

### APC Supported TR-31 Key Usage Codes

```yaml
id: reference_list.apc-tr31-key-usages
entity_type: reference_list
canonical_name: APC Supported TR-31 Key Usage Codes
summary: >
  Complete TR-31 key usage codes supported by AWS Payment Cryptography, their permitted
  algorithms, and operational notes. Source: APC valid-attributes documentation (accessed 2026-05-19).
domain:
  - key_management
  - cryptography
attributes:
  P0_PIN_ENCRYPTION_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    note: AES P0 keys require ISO Format 4 PIN blocks
  C0_CARD_VERIFICATION_KEY:
    algorithms: [TDES_2KEY]
    note: CVV1, CVV2, iCVV, dCVV, Amex CSC1/CSC2/iCSC/AEVV; TDES_2KEY only
  D0_DATA_ENCRYPTION_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
  D1_ASYMMETRIC_DATA_ENCRYPTION_KEY:
    algorithms: [RSA_2048, RSA_3072, RSA_4096]
  E0_EMV_MKEY_APP_CRYPTOGRAMS:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    mode: DeriveKey only
    note: ARQC/TC/AAC master key
  E1_EMV_MKEY_CONFIDENTIALITY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    mode: DeriveKey only
    note: EMV secure messaging encryption master key
  E2_EMV_MKEY_INTEGRITY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    mode: DeriveKey only
    note: EMV secure messaging MAC master key; used by GenerateMacEmvPinChange
  E4_EMV_MKEY_DYNAMIC_NUMBERS:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128]
    mode: DeriveKey only
    note: dCVV, Mastercard DCVC3, Visa CVN17 dynamic card values
  E5_EMV_MKEY_CARD_PERSONALIZATION:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128]
    mode: DeriveKey only
  E6_EMV_MKEY_OTHER:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128]
    mode: DeriveKey only
  M1_ISO9797_1_MAC_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY]
  M3_ISO9797_3_MAC_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY]
  M6_ISO9797_5_CMAC_KEY:
    algorithms: [AES_128, AES_192, AES_256]
    note: AES-CMAC MAC key
  M7_HMAC_KEY:
    algorithms: [HMAC_SHA256, HMAC_SHA384, HMAC_SHA512]
    note: Used for Mastercard SPA2 AAV via GenerateMac
  K0_KEY_ENCRYPTION_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    note: Legacy; functionally equivalent to K1 in APC
  K1_KEY_BLOCK_PROTECTION_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256]
    note: Preferred KBPK usage per X9.143
  K2_TR34_ASYMMETRIC_KEY:
    algorithms: [RSA_2048, RSA_3072, RSA_4096]
    note: Public key for TR-34 key transport
  K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT:
    algorithms: [ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521]
    note: ECDH; DeriveKeyUsage fixed at creation
  V1_IBM3624_PIN_VERIFICATION_KEY:
    algorithms: [TDES_2KEY]
    note: APC operationally enforces TDES_2KEY
  V2_VISA_PIN_VERIFICATION_KEY:
    algorithms: [TDES_2KEY]
    note: APC operationally enforces TDES_2KEY for PVV
  B0_BASE_DERIVATION_KEY:
    algorithms: [TDES_2KEY, TDES_3KEY, AES_128, AES_256]
    note: DUKPT BDK for TDES or AES DUKPT
  S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE:
    algorithms: [RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521]
status: active
```

### TR-31 Optional Header Fields (APC)

```yaml
id: artifact.tr31-optional-header-fields
entity_type: artifact
canonical_name: TR-31 Key Block Optional Header Fields
aliases:
  - TR-31 optional blocks
  - key block optional headers
summary: >
  TR-31 key blocks may carry two-character optional header field IDs after the core header.
  APC reads and writes specific fields on import/export to convey supplementary key context.
domain:
  - key_management
  - cryptography
attributes:
  BI:
    name: BDK Identifier
    description: Identifies the BDK that generated this IPEK/IK
    tdes_format: 2-hex type + 10-hex KSI
    aes_format: 2-hex type + 8-hex BDK ID
    apc: auto-populated on IPEK/IK export
  HM:
    name: HMAC hash algorithm
    description: Hash algorithm for HMAC (M7) keys
    apc: auto-populated on export; parsed on import
  IK:
    name: AES DUKPT initial KSN
    description: 16 hex chars; IKI (derivation data, no counter)
    apc: populated on AES DUKPT IK export
  KS:
    name: TDES DUKPT initial KSN
    description: 20 hex chars; full KSN with counter zeroed
    apc: populated on TDES DUKPT IPEK export
  KP:
    name: KCV of wrapping KBPK
    description: method byte (00=ANSI_X9_24, 01=CMAC) + 6-hex KCV of wrapping key
    apc: auto-populated on export; lets receiver confirm they used the correct KEK
  PB:
    name: Padding block
    description: Auto-calculated to align total block length to a multiple of 8 bytes
    apc: never set manually; auto-calculated
relationships:
  - type: related_to
    target_id: key-block.tr31
  - type: related_to
    target_id: artifact.ksn
  - type: related_to
    target_id: key-type.bdk
constraints:
  - PB is always auto-calculated; manually setting it will corrupt the block
  - BI and IK/KS link an exported IPEK/IK back to its parent BDK for future re-derivation
status: active
```

### EMV CVN Variant to APC Session Key Derivation Attribute

```yaml
id: reference_list.emv-cvn-to-apc-session-key-attribute
entity_type: reference_list
canonical_name: EMV CVN Variant to APC SessionKeyDerivation Attribute
summary: >
  Maps EMV Cryptogram Version Number (CVN) to the APC SessionKeyDerivation attribute used
  in GenerateCardValidationData, VerifyCardValidationData, and GenerateAuthRequestCryptogram.
domain:
  - emv
  - card_validation
  - key_management
attributes:
  visa:
    CVN10: {apc_attribute: Visa, note: per-card master key derivation (SDA)}
    CVN18: {apc_attribute: EmvCommon, note: Common Session Key per EMVCo spec}
    CVN22: {apc_attribute: EmvCommon, note: CSK variant}
    CVN01: {apc_attribute: Visa, note: shared attribute code with CVN10}
    CVN17:
      apc_attribute: EmvCommon (dynamic)
      key_usage: TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS
      generation_attribute: DynamicCardVerificationValue
      note: Visa dCVV; uses E4 master key with DeriveKey
  mastercard:
    CVN14: {apc_attribute: EmvCommon, note: CSK}
    CVN15: {apc_attribute: EmvCommon, note: CSK variant}
    CVN12: {apc_attribute: MastercardSessionKey, note: uses unpredictable number in derivation}
    CVN13: {apc_attribute: MastercardSessionKey, note: like CVN12 with different diversification}
  jcb:
    CVN04: {apc_attribute: EmvCommon, note: JCB CSK}
    CVN01: {apc_attribute: Visa, note: per-card derivation, shared attribute with Visa CVN10}
  arpc_methods:
    Method_1: ARQC XOR 4-byte response code; simple XOR response
    Method_2: MAC over 8-byte Card Status Update (CSU) + proprietary auth data; primary method in APC examples
  apc_key_usages:
    arqc_generation: TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS
    integrity_mac: TR31_E2_EMV_MKEY_INTEGRITY
    confidentiality: TR31_E1_EMV_MKEY_CONFIDENTIALITY
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: artifact.arpc
  - type: related_to
    target_id: algorithm.emv-key-derivation
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
status: active
```

## APC Constraint Rules

### APC: Wrapping Key Strength Enforcement

```yaml
id: rule.apc-key-wrapping-strength
entity_type: constraint_rule
canonical_name: APC Wrapping Key Strength Enforcement
summary: >
  APC automatically rejects key import/export operations where the wrapping key is weaker
  than the key being wrapped. This is enforced server-side; no client-side workaround exists.
domain:
  - key_management
  - cryptography
constraints:
  - RSA_2048 can wrap TDES keys only (2KEY or 3KEY)
  - RSA_3072 or RSA_4096 can wrap TDES or AES-128
  - RSA cannot wrap AES-192 or AES-256; use ECDH instead
  - AES-128 KBPK can wrap TDES or AES-128 (not AES-192 or AES-256)
  - AES-256 KBPK can wrap any supported symmetric key
  - ECDH is the only path for AES-256 key transport
relationships:
  - type: related_to
    target_id: key_type.kbpk
  - type: related_to
    target_id: concept.apc-ecdh-key-agreement
  - type: related_to
    target_id: rule.apc-rsa-wrap-padding
status: active
```

### APC: TR-31 Version Selection Is Automatic

```yaml
id: rule.apc-tr31-version-selection
entity_type: constraint_rule
canonical_name: APC TR-31 Key Block Version Selection
summary: >
  APC selects the TR-31 version automatically based on the wrapping KBPK's algorithm.
  Callers cannot override the version on export. Versions A and C are accepted for
  import only (legacy compatibility).
domain:
  - key_management
  - cryptography
constraints:
  - TDES KBPK → TR-31 version B (2-key TDES MAC)
  - AES KBPK → TR-31 version D (AES-CMAC)
  - Versions A and C: import-only; legacy key loading support
  - Version selection on export is automatic and non-configurable
relationships:
  - type: related_to
    target_id: key-block.tr31
  - type: related_to
    target_id: key_type.kbpk
status: active
```

### APC: ISO Format 4 Required for AES PIN Keys

```yaml
id: rule.apc-format4-aes-pin-requirement
entity_type: constraint_rule
canonical_name: APC ISO Format 4 Required for AES PIN Encryption Keys
summary: >
  When the PIN encryption key in an APC operation is AES (any AES length), the PIN
  block format must be ISO 9564 Format 4. APC rejects Formats 0, 1, and 3 when an
  AES P0 key is specified.
domain:
  - pin_processing
  - cryptography
constraints:
  - AES P0 key + Format 0/1/3 → APC validation error
  - AES P0 key + Format 4 → correct
  - TDES P0 key + Format 0/1/3 → correct
  - Format 4 uses double-pass AES ECB encryption with PAN as tweak
relationships:
  - type: related_to
    target_id: format.pin-block-format-4
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
status: active
```

### APC: IPEK/IK Not Persisted After Export

```yaml
id: rule.apc-ipek-not-persisted
entity_type: constraint_rule
canonical_name: APC IPEK/IK Is Derived On Demand and Not Stored
summary: >
  When APC exports a DUKPT IPEK (TDES) or IK (AES), it derives the key on demand from
  the BDK and does not persist it. Each export re-derives independently. The KSN counter
  is ignored during IPEK/IK derivation.
domain:
  - key_management
  - cryptography
constraints:
  - IPEK/IK cannot be referenced by ARN for subsequent APC data-plane operations
  - KSN counter bits are ignored; same IPEK results for any counter value on the same device
  - The BDK must remain in APC to re-derive the same IPEK/IK
relationships:
  - type: related_to
    target_id: key-type.ipek
  - type: related_to
    target_id: key-type.bdk
  - type: related_to
    target_id: algorithm.dukpt
status: active
```

### APC: Key Attributes Are Immutable After Creation

```yaml
id: rule.apc-key-attributes-immutable
entity_type: constraint_rule
canonical_name: APC Key Attributes Are Immutable Post-Creation
summary: >
  A key's algorithm, key length, usage, class, and origin cannot be changed after
  creation or import. Key rotation is achieved by creating a new key and reassigning
  the alias.
domain:
  - key_management
constraints:
  - To change algorithm or usage, create a new key and redirect the consuming alias
  - Effective date, expiry date, and tags are the only mutable attributes
  - KeyOrigin (AWS_PAYMENT_CRYPTOGRAPHY vs EXTERNAL) is immutable
relationships:
  - type: related_to
    target_id: concept.apc-key-lifecycle
status: active
```

### APC: PVK Must Be TDES_2KEY for PVV/IBM 3624

```yaml
id: rule.apc-pvk-tdes2key-only
entity_type: constraint_rule
canonical_name: APC PVK Must Be TDES_2KEY for PIN Verification Operations
summary: >
  Although the APC valid-attributes table may list additional algorithms alongside PIN
  verification key usages, PVV and IBM 3624 PIN operations require TDES_2KEY. Other
  algorithm variants are schema-defined but not operationally active.
domain:
  - pin_processing
  - cryptography
constraints:
  - GeneratePinData / VerifyPinData with VISA_PVV require TDES_2KEY PVK (TR31_V2)
  - GeneratePinData / VerifyPinData with IBM_3624 require TDES_2KEY PVK (TR31_V1)
  - Using a non-TDES_2KEY PVK produces an APC validation error
relationships:
  - type: related_to
    target_id: algorithm.visa-pin
  - type: related_to
    target_id: algorithm.ibm-3624
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
status: active
```

### APC: KCV Algorithm by Key Type

```yaml
id: rule.apc-kcv-algorithm-by-key-type
entity_type: constraint_rule
canonical_name: APC KCV Algorithm Depends on Key Type
summary: >
  APC computes KCVs automatically and returns the method used alongside the value.
  The algorithm differs by key type.
domain:
  - key_management
  - cryptography
constraints:
  - TDES keys → ANSI_X9_24 (encrypt 8 zero bytes; top 3 bytes = KCV)
  - AES keys → CMAC (AES-CMAC over 16 zero bytes; top 3 bytes = KCV)
  - Asymmetric keys (RSA, ECC) → SHA_1 of public key; top 3 bytes = KCV
  - APC returns the KCV method identifier alongside every KCV value in key management responses
relationships:
  - type: related_to
    target_id: artifact.kcv
  - type: related_to
    target_id: rule.kcv-validation-after-transfer
status: active
```

### APC: RSA Wrap Padding Requirements

```yaml
id: rule.apc-rsa-wrap-padding
entity_type: constraint_rule
canonical_name: APC RSA Key Wrap Must Use OAEP Padding
summary: >
  APC uses RSA-OAEP padding for all RSA key wrap operations. PKCS#1 v1.5 is not
  supported. RSA wrap is also limited to TDES and AES-128; AES-192/256 requires ECDH.
domain:
  - key_management
  - cryptography
constraints:
  - RSA_OAEP_SHA_256 and RSA_OAEP_SHA_512 are the only supported padding modes
  - PKCS#1 v1.5 padding is explicitly not supported
  - RSA key wrap supports TDES and AES-128 wrapped keys only; AES-192/256 requires ECDH
relationships:
  - type: related_to
    target_id: rule.apc-key-wrapping-strength
status: active
```

### APC: EMV Master Key Usages Are DeriveKey-Only

```yaml
id: rule.apc-emv-master-key-derive-only
entity_type: constraint_rule
canonical_name: APC EMV Master Keys Must Be Created with DeriveKey
summary: >
  Keys with TR-31 usages E0 through E6 (EMV master keys) can only be created in APC
  with DeriveKey=true or NoRestrictions=true. They cannot be configured for direct
  encrypt or decrypt operations.
domain:
  - key_management
  - emv
  - cryptography
constraints:
  - E0 (app cryptograms), E1 (confidentiality), E2 (integrity), E4 (dynamic numbers),
    E5 (personalization), E6 (other) — all require DeriveKey mode
  - Attempting to create an E-usage key without DeriveKey produces an APC validation error
  - Session keys derived from E-usage master keys can then perform the actual crypto operations
relationships:
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
  - type: related_to
    target_id: algorithm.emv-key-derivation
status: active
```

### APC: GenerateMac mac_length Is in Nibbles (Hex Digits), Not Bytes

```yaml
id: rule.apc-generate-mac-length-nibbles
entity_type: constraint_rule
canonical_name: APC GenerateMac mac_length Parameter Is in Nibbles
summary: >
  The mac_length parameter of APC GenerateMac specifies the output length in nibbles
  (hexadecimal digits), not bytes. Passing 8 returns a 4-byte (8 hex char) MAC. Pass 16
  for a full 8-byte MAC. This differs from the natural expectation of byte-length.
domain:
  - cryptography
  - key_management
constraints:
  - mac_length=8 → 4-byte output (8 hex chars)
  - mac_length=16 → 8-byte output (16 hex chars); this is the standard payment MAC size
  - Passing a byte count (e.g. 8 when 8 bytes are needed) silently produces a truncated result
examples:
  - "GenerateMac with mac_length=16 returns a full 8-byte ISO 9797 MAC"
relationships:
  - type: related_to
    target_id: operation.apc-generate-mac
status: active
```

### APC: ISO 9797-1 Algorithm 3 Uses Method 1 (Zero Padding)

```yaml
id: rule.apc-iso9797-algorithm3-method1
entity_type: constraint_rule
canonical_name: APC ISO 9797-1 Algorithm 3 Always Uses Padding Method 1
summary: >
  APC GenerateMac and VerifyMac with MacAlgorithm=ISO9797_ALGORITHM3 apply ISO 9797-1
  Padding Method 1 (zero-pad to block boundary). They do not support Method 2 (ISO 7816-4
  append 0x80 then zeros). Any MAC computed with Method 2 will not verify against APC.
domain:
  - cryptography
constraints:
  - APC ISO9797_ALGORITHM3 → Method 1 (right-pad with 0x00)
  - Method 2 (ISO 7816-4: append 0x80 then zeros) is not supported by APC for this algorithm
  - EMV issuer-script MAC operations often use Method 2 — these will NOT match APC GenerateMac output
  - To produce an APC-compatible MAC, use explicit Method 1 in the client MAC library
examples:
  - "CyberChef 'MAC Generate' with ISO 9797-3 Method 1 matches APC; 'EMV Generate MAC' now exposes a padding method selector (default Method 2)"
relationships:
  - type: related_to
    target_id: algorithm.iso9797-algorithm3
  - type: related_to
    target_id: rule.apc-generate-mac-length-nibbles
status: active
```

### APC: DUKPT TDES Data Encryption Uses Directional Variants, Not ANSI X9.24-1 "Data" Variant

```yaml
id: rule.apc-dukpt-tdes-data-variant
entity_type: constraint_rule
canonical_name: APC DUKPT TDES Data Encryption Uses REQUEST/RESPONSE/BIDIRECTIONAL, Not ANSI X9.24-1 Data Variant
summary: >
  APC EncryptData / DecryptData with DUKPT TDES accepts DukptKeyVariant values of
  BIDIRECTIONAL, REQUEST (outgoing/encrypt direction), and RESPONSE (incoming/decrypt
  direction). These are a directional model, not the ANSI X9.24-1 named variants (None,
  PIN, MAC Request, MAC Response, Data). The XOR byte positions APC uses for data
  REQUEST/RESPONSE/BIDIRECTIONAL are not published. Empirical testing against all five
  ANSI X9.24-1 named variants confirmed none produces the same ciphertext as APC.
  APC is internally self-consistent (encrypt-then-decrypt roundtrip works) but output
  is not interoperable with ANSI X9.24-1 "Data" variant implementations.
  For MAC, APC REQUEST maps to ANSI X9.24-1 "MAC Request" (bytes 6 and 14 XOR 0xFF);
  no equivalent mapping is known for data encryption.
domain:
  - cryptography
  - key_management
attributes:
  apc_dukpt_key_variants_for_data:
    REQUEST: outgoing data encryption direction — VALID for TDES_2KEY BDK
    RESPONSE: incoming data decryption direction — VALID for TDES_2KEY BDK
    BIDIRECTIONAL: INVALID for TDES_2KEY BDK (returns "Invalid DukptKeyVariant provided
      for key algorithm"); BIDIRECTIONAL is an AES DUKPT-only variant
    NO_VARIANT: omitting DukptKeyVariant entirely defaults to REQUEST behavior
      (produces identical ciphertext to explicit REQUEST)
  apc_tdes_2key_bdk_derivation_type:
    valid: TDES_2KEY only — specifying TDES_3KEY for a TDES_2KEY BDK returns
      "DUKPT derivation type TDES_3KEY is invalid for the corresponding key algorithm"
  apc_tdes_dukpt_ciphertexts_confirmed_2026_05_20:
    BDK: 0123456789ABCDEFFEDCBA9876543210 (KCV=08D7B4)
    KSN: FFFF9876543210E00001
    plaintext: 0102030405060708 (ECB, single block)
    REQUEST: 124F7A32F3F84187
    RESPONSE: 3C4DC2BD394544E2
    ciphertext_xor_REQUEST_RESPONSE: 2E02B88FCABD0565
    note: >
      What was previously labeled "APC BIDIRECTIONAL ciphertext" in this KB was actually
      the REQUEST ciphertext. The BIDIRECTIONAL call was never valid for TDES_2KEY and
      the prior test had silently defaulted to REQUEST behavior.
  ansi_x9_24_1_data_variant: bytes 5 and 13 of session key XOR 0xFF (does not match any APC variant)
  mac_variant_alignment: APC REQUEST for MAC = ANSI X9.24-1 MAC Request (bytes 6,14); no data equivalent known
  thales_hypothesis: >
    APC was designed to be a drop-in for existing Thales payShield acquirer deployments.
    DISPROVEN FOR LEGACY COMMAND SET (2026-05-19): The Thales payShield 10K Legacy Host
    Commands (Version V1, 2019, PUGD0538-002) was read in full. There is no M0 command.
    The DUKPT section (Section 6) contains only five commands (CI/CK/CM/CO/CQ) and all
    are PIN-only — there is no DUKPT data encryption command in the legacy set. Data
    encryption (XW/XU commands) accepts a pre-supplied session data key under LMK pair
    30-31, not a BDK+KSN derivation; those commands cannot be the source of APC's variant.
    The legacy doc references modern replacement commands G0/GQ/GS/GU for DUKPT PIN
    translate; these and any modern DUKPT data command would be in the non-legacy payShield
    Host Commands reference (separate document, not yet reviewed). If the variant origin
    still matters, the next investigation target is the modern Thales payShield Host Commands
    reference. Futurex interop hypothesis remains plausible but cannot be confirmed from
    legacy docs alone.
  exhaustive_ruling_out_2026_05_20: >
    Empirical testing with test vector (BDK=0123456789ABCDEFFEDCBA9876543210,
    KSN=FFFF9876543210E00001, plaintext=0102030405060708) has ruled out ALL of:
    (1) All 8 single-byte-pair XOR positions (bytes n and n+8 XOR 0xFF, n=0..7) — ANSI X9.24-1 variants.
    (2) KL/KR swap (KR || KL) with each of the 5 standard variant masks.
    (3) Speculative "Table 4" multi-byte masks (no cited source; empirically false).
    (4) Alternative TDES key expansion arrangements (LRR, RLR, RRL, RLL, LLR) with all variants.
    (5) CBC with IV=all-zeros.
    (6) Single-byte-pair XOR, ANY value 0x01-0xFF, all 8 positions — 2040 candidates, no match
        against either REQUEST (124F7A32F3F84187) or RESPONSE (3C4DC2BD394544E2).
    (7) 2-byte-pair XOR (symmetric mirrors: same value for byte[n] and byte[n+8]), ALL C(8,2)=28
        pairs × all value combos — ~1.8M candidates, no match.
    (8) Asymmetric single-byte XOR (left half only or right half only, any position, any value)
        — no match.
    (9) AES-CMAC-based derivation (X9.24-3 style, 2026-05-20): tested CMAC(BDK, derivation_data)
        where derivation_data used the X9.24-3 standard format (version || key_usage || algo ||
        length || counter) across all plausible key usage codes for REQUEST/RESPONSE (data
        encryption, data decryption, MAC generation, MAC verification, PIN, and values 0x0006–0x0009),
        with TDES-2KEY and AES-128 algo fields, and both 64-bit and 128-bit length fields.
        Also tested: CMAC(BDK, KSN) raw; CMAC(BDK, KSN zero-padded to 12/16 bytes);
        two-step chain CMAC(BDK, ksn_base) → CMAC(ik, counter); CMAC(BDK, KSN || usage_byte)
        for all plausible request/response byte suffix pairs. ZERO matches against either
        REQUEST (124F7A32F3F84187) or RESPONSE (3C4DC2BD394544E2).
    CONCLUSION: APC TDES DUKPT data key derivation is neither a post-derivation XOR mask
    (ANSI X9.24-1 style) nor an AES-CMAC-based derivation (X9.24-3 style). The algorithm
    is non-standard and requires AWS documentation or an AWS support case to resolve.
constraints:
  - APC DUKPT TDES data encryption: use DukptKeyVariant=REQUEST for outgoing, RESPONSE for incoming
  - BIDIRECTIONAL is invalid for TDES_2KEY — it is an AES DUKPT-only variant in APC
  - Omitting DukptKeyVariant defaults to REQUEST behavior (identical ciphertext)
  - TDES_3KEY derivation type rejected for TDES_2KEY BDK — only TDES_2KEY is valid
  - APC's REQUEST/RESPONSE data ciphertexts do not match ANY post-derivation XOR mask structure
  - DUKPT MAC aligns: APC DukptKeyVariant=REQUEST for MAC = ANSI X9.24-1 MAC Request (bytes 6,14)
  - Migrate to AES DUKPT (ANSI X9.24-3) for a fully published, unambiguous derivation algorithm
examples:
  - "BDK=0123456789ABCDEFFEDCBA9876543210, KSN=FFFF9876543210E00001, plaintext=0102030405060708:
     ANSI X9.24-1 Data variant ciphertext=92A5157E4607D1B0,
     APC REQUEST ciphertext=124F7A32F3F84187,
     APC RESPONSE ciphertext=3C4DC2BD394544E2
     (all XOR-mask-based approaches exhaustively tested; none matched)"
relationships:
  - type: related_to
    target_id: algorithm.dukpt
  - type: related_to
    target_id: key-type.bdk
status: active
```

### APC: ARQC Verification Requires AES-256 E0 Master Key

```yaml
id: rule.apc-arqc-aes256-required
entity_type: constraint_rule
canonical_name: APC VerifyAuthRequestCryptogram Requires AES-256 E0 Key
summary: >
  APC VerifyAuthRequestCryptogram rejects AES-128 E0 (TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS)
  keys with an invalid key algorithm error. An AES-256 E0 master key is required for APC
  ARQC verification. TDES E0 keys work for TDES ARQC. This constraint is not documented
  in the APC public API reference.
domain:
  - emv
  - cryptography
constraints:
  - AES-128 E0 → VerifyAuthRequestCryptogram returns "KeyAlgorithm of the input key is invalid"
  - AES-256 E0 → accepted for AES ARQC verification
  - TDES E0 (TDES_2KEY or TDES_3KEY) → accepted for TDES ARQC verification
  - AES ARQC computation itself (AES-CMAC with Option A session key derivation) is correct for AES-128;
    only APC verification rejects AES-128
examples:
  - "emv_e0=101112131415161718191A1B1C1D1E1F (AES-128), ATC=0001:
     sessionKey=EC1EBB481BE674B22456BD15F98843DB, ARQC=8C8E19CED4DBBF59 (correct per spec).
     APC rejected the key — AES-256 E0 required for APC cross-validation."
relationships:
  - type: related_to
    target_id: artifact.arqc
  - type: related_to
    target_id: algorithm.emv-key-derivation
  - type: related_to
    target_id: rule.apc-emv-master-key-derive-only
status: active
```

### APC: D0 / E0 / P0 Keys Require NoRestrictions Mode

```yaml
id: rule.apc-d0-e0-p0-norestrictions
entity_type: constraint_rule
canonical_name: APC D0, E0, and P0 Keys Require NoRestrictions Mode on Import
summary: >
  APC rejects symmetric key imports for D0 (data encryption), E0 (EMV app cryptograms),
  and P0 (PIN encryption) usages when specific KeyModesOfUse combinations are supplied.
  Only NoRestrictions=true is accepted for these usage types on import via KEY_CRYPTOGRAM.
domain:
  - key_management
  - cryptography
constraints:
  - D0 with Encrypt+Decrypt → rejected; use NoRestrictions=true
  - E0 with Generate or Verify → rejected; use NoRestrictions=true
  - P0 with Encrypt → rejected; use NoRestrictions=true
  - NoRestrictions=true bypasses mode enforcement and is the only import-compatible option
    for these three usage types
  - Side effect: D0 keys imported with NoRestrictions are then rejected by re_encrypt_data
    ("KeyUsages not allowed for this operation") — APC does not permit re-encrypt on
    unrestricted D0 keys
relationships:
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
  - type: related_to
    target_id: rule.apc-reencrypt-norestrictions-blocked
status: active
```

### APC: ReEncryptData Blocked for D0 Keys with NoRestrictions

```yaml
id: rule.apc-reencrypt-norestrictions-blocked
entity_type: constraint_rule
canonical_name: APC ReEncryptData Rejects D0 Keys Imported with NoRestrictions
summary: >
  APC ReEncryptData requires that D0 keys carry explicit Encrypt and Decrypt modes.
  D0 keys imported with NoRestrictions=true (the only import-compatible mode) are
  rejected by ReEncryptData with a "KeyUsages not allowed" error. There is no workaround
  within the KEY_CRYPTOGRAM import path; keys intended for ReEncryptData must be imported
  with explicit Encrypt+Decrypt mode via TR-31 or TR-34 if those paths are available.
domain:
  - key_management
  - cryptography
constraints:
  - ReEncryptData + D0 key with NoRestrictions=true → "KeyUsages not allowed for this operation"
  - D0 with Encrypt+Decrypt mode cannot be imported via KEY_CRYPTOGRAM (APC rejects the modes)
  - This is an APC API constraint; it is not a deficiency in the plaintext key material
relationships:
  - type: related_to
    target_id: rule.apc-d0-e0-p0-norestrictions
  - type: related_to
    target_id: reference_list.apc-tr31-key-usages
status: active
```

### APC: KEY_CRYPTOGRAM Import Requirements

```yaml
id: concept.apc-key-cryptogram-import
entity_type: concept
canonical_name: APC KEY_CRYPTOGRAM Import Operational Requirements
summary: >
  Key import via the KEY_CRYPTOGRAM method (RSA-OAEP wrapped symmetric key) has several
  non-obvious requirements discovered through direct API testing. All must be satisfied
  for a successful import.
domain:
  - key_management
  - cryptography
attributes:
  required_parameters:
    KeyClass: SYMMETRIC_KEY  # must be explicit; omitting causes "Missing required parameter" error
    Exportable: false  # required inside the KeyCryptogram sub-object
    KeyCheckValueAlgorithm: >
      top-level parameter to import_key, NOT inside KeyCryptogram; placing it inside
      KeyCryptogram causes a validation error
  wrapped_key_encoding:
    format: HEX uppercase  # WrappedKeyCryptogram must be hex, not base64
    common_mistake: base64-encoding the RSA OAEP output
  wrapping_padding: RSA_OAEP_SHA_256 (RSA_OAEP_SHA_512 also accepted)
  rsa_certificate_quirk: >
    The APC-returned RSA wrapping certificate contains an ASN.1 extension that causes
    Node.js X509Certificate and .NET X509Certificate2 to fail during SPKI extraction.
    Workaround: manually extract SPKI from the DER bytes at offset 265 (length 422),
    save as a .der file, and load with createPublicKey({format:'der', type:'spki'}).
    Verified with APC RSA-3072 wrapping certificate (2026-05-19).
constraints:
  - KeyClass: SYMMETRIC_KEY must be present in KeyAttributes
  - WrappedKeyCryptogram must be hex string, not base64
  - KeyCheckValueAlgorithm is a top-level import_key parameter
  - Exportable: false must be set inside the KeyCryptogram sub-object
  - For D0/E0/P0 keys, use NoRestrictions:true in KeyModesOfUse (see rule.apc-d0-e0-p0-norestrictions)
relationships:
  - type: related_to
    target_id: rule.apc-rsa-wrap-padding
  - type: related_to
    target_id: rule.apc-d0-e0-p0-norestrictions
status: active
```

### APC: IBM 3624 VerifyPinData Requires PinValidationDataPadCharacter

```yaml
id: rule.apc-ibm3624-pad-char-required
entity_type: constraint_rule
canonical_name: APC VerifyPinData IBM 3624 Requires PinValidationDataPadCharacter
summary: >
  APC VerifyPinData with IBM 3624 verification attributes requires the
  PinValidationDataPadCharacter field. Omitting it causes a validation error.
  The pad character is the fill nibble used in the decimalization output ('F' is common).
domain:
  - pin_processing
  - cryptography
constraints:
  - VerifyPinData + VerificationMethod=IBM_3624 + missing PinValidationDataPadCharacter → validation error
  - Typical value is 'F' (hex 0xF fill nibble used by most IBM 3624 implementations)
  - The GeneratePinData path for IBM 3624 has the same requirement
examples:
  - "verification_attributes: {Algorithm: IBM_3624, PinValidationData: '43210', PinValidationDataPadCharacter: 'F', ...}"
relationships:
  - type: related_to
    target_id: algorithm.ibm-3624
  - type: related_to
    target_id: rule.apc-pvk-tdes2key-only
status: active
```

### APC: GeneratePinData VISA PVV Emits ISO Format 0 Compliance Warning

```yaml
id: rule.apc-generate-pin-data-iso0-compliance-warning
entity_type: constraint_rule
canonical_name: APC GeneratePinData Issues Compliance Warning for ISO Format 0
summary: >
  APC GeneratePinData for VISA PVV with an ISO Format 0 encrypted PIN block input emits
  a PCI compliance warning in the response because ISO Format 0 is a legacy format. The
  operation still proceeds. VerifyPinData does not emit this warning. For production use,
  APC recommends ISO Format 4 with AES keys.
domain:
  - pin_processing
  - cryptography
constraints:
  - GeneratePinData + VisaPinVerificationValue + ISO Format 0 PIN block → response includes compliance warning
  - Warning does not block the operation; the PVV is computed and returned
  - VerifyPinData with the same inputs does not emit the warning
  - Prefer ISO Format 4 with AES P0 key in production to avoid the warning
relationships:
  - type: related_to
    target_id: format.pin-block-format-0
  - type: related_to
    target_id: rule.apc-format4-aes-pin-requirement
  - type: related_to
    target_id: algorithm.visa-pin
status: active
```

## PCI PIN Security Requirements — Acquirer-Relevant Rules

Source: PCI PTS PIN Security Requirements Technical FAQs v3, June 2021 (listings.pcisecuritystandards.org).
These rules are the compliance layer that governs how acquirers operate HSMs and manage keys.
APC as a cloud HSM satisfies the physical and certification requirements; the procedural rules below
still bind the acquirer operating APC.

---

### PCI PIN: TR-31 Key Blocks Required for BDKs and Initial DUKPT Keys

```yaml
id: concept.pci-pin-key-block-requirements
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 18 — TR-31 Key Blocks for BDKs and Initial DUKPT Keys
summary: >
  PCI PIN Security Requirement 18 mandates that encrypted symmetric keys be managed in
  structures called key blocks (TR-31 or ISO 20038). This applies to BDKs and initial
  DUKPT keys. Per-transaction DUKPT working keys are EXEMPT provided they remain inside
  an SCD at all times. Key blocks apply to both conveyance and storage.
  TR-31 is the standard method; any equivalent method must include cryptographic binding
  of key-usage information and must undergo independent expert review that is publicly available.
  All three rollout phases are now past their deadlines.
domain:
  - key_management
  - compliance
attributes:
  applies_to:
    - BDKs (Base Derivation Keys)
    - initial DUKPT keys
    - TMKs (Terminal Master Keys)
    - ZMKs (Zone Master Keys) and KEKs
    - PEKs (PIN Encryption Keys) in host-to-host transport
    - any symmetric key outside an SCD
  exempt:
    - per-transaction DUKPT working keys stored inside an SCD
    - issuer keys: PVV, CVV, EMV personalization keys (not in scope for PCI PIN key block
      requirement; key blocks recommended as best practice but not mandated — Q13)
  standards: ["ANSI TR-31", "ISO 20038"]
  rollout_phases:
    phase_1: "2019-06-01 — internal connections and key storage within Service Provider environments (all applications and databases connected to HSMs)"
    phase_2: "2023-01-01 — external connections to Associations and Networks"
    phase_3: "2025-01-01 — all merchant hosts, point-of-sale (POS) devices and ATMs"
  tr31_key_hierarchy:
    kbpk: "Key-Block Protection Key — wraps the payload; used for no other purpose"
    kbek: "Key-Block Encryption Key — derived from KBPK; encrypts the key payload"
    kbak: "Key-Block Authentication Key — derived from KBPK; MACs the block header+payload"
  previously_established_keys: >
    Entities are not required to reissue existing KEKs solely to comply with Req 18.
    Previously established keys can remain in use until they are next exchanged (Q4).
constraints:
  - BDKs and initial DUKPT keys must be conveyed and stored in TR-31 key blocks
  - Per-transaction working keys inside an SCD do not need key blocks
  - APC imports/exports keys via TR-31; this requirement is met by the APC import flow
  - Any proprietary key block equivalent requires an independent expert review (doctoral-level
    cryptography credentials, 10+ years experience) that is publicly available
  - Key block requirement and fixed-key TDES ban (Req 18-2) are INDEPENDENT requirements
    with no relationship between them — complying with one does not satisfy the other (Q7)
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q28 (Req 18), Q29, Q30, Q31, Q33, Q34"
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §18-3 (normative phase dates)"
  - "PCI Information Supplement: PIN Security Req 18-3 Key Blocks, June 2019 (Q4, Q7, Q13)"
relationships:
  - type: related_to
    target_id: algorithm.tr31
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
status: active
```

---

### PCI PIN: BDK Segmentation Required

```yaml
id: concept.pci-pin-bdk-segmentation
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 20 — BDK Segmentation by FI, Vendor, and Geography
summary: >
  Entities processing or injecting DUKPT must implement a BDK segmentation strategy.
  Segmentation dimensions include: different BDKs per financial institution (sponsor),
  per injection vendor / ESO / terminal manufacturer or model, and per geographic region,
  market segment, or processing platform. A single BDK may cover an entire POI population
  only if the entity has exactly one financial institution sponsor, one injection vendor,
  and operates within a single geographic region.
domain:
  - key_management
  - compliance
attributes:
  segmentation_dimensions:
    - financial_institution_sponsor
    - injection_vendor_or_ESO
    - terminal_manufacturer_or_model
    - geographic_region
    - market_segment_or_processing_platform
  single_bdk_allowed_when:
    - exactly one FI sponsor
    - exactly one injection vendor
    - within one geographic region (e.g., within the US)
constraints:
  - Multi-sponsor or multi-vendor acquirers must use separate BDKs per FI and per injection vendor
  - APC models BDKs as TR31_B0_BASE_DERIVATION_KEY; create one APC BDK alias per required segment
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q36 (Req 20)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: key-type.bdk
status: active
```

---

### PCI PIN: Cloud HSM (HSM-as-a-Service) Compliance Path

```yaml
id: concept.pci-pin-cloud-hsm-compliance
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 1 — Cloud HSM Is Permitted; Acquirer Remains Responsible
summary: >
  An acquirer may use a third-party hosted HSM service (HSM in the cloud). The acquirer
  is responsible for ensuring all PCI PIN requirements are met by the cloud HSM provider.
  When a cloud provider houses HSMs in a third-party data center, specific controls apply:
  the cloud provider must control all logical access (data center ops staff must have no
  logical admin access); CCTV must be positioned per Annex B requirements and stream to
  a cloud-provider-controlled server; cabinet access must be dual-control (cloud provider
  staff badge/biometric, or pre-authorized data center staff under dual control with
  monitoring, authorization, identity verification, and activity monitoring).
  APC satisfies these requirements as a PCI PTS HSM V3 and FIPS 140-2 Level 3 certified service.
domain:
  - compliance
  - hsm
attributes:
  apc_certification: "PCI PTS HSM V3, FIPS 140-2 Level 3"
  acquirer_responsibility: true
  cloud_provider_requirements:
    - no logical access for data center ops staff
    - CCTV per Annex B, streaming to cloud provider server
    - dual-control cabinet access with monitoring and identity verification
constraints:
  - APC satisfies HSM certification; acquirer must still implement procedural controls on their side
  - Acquirer must verify APC's compliance attestation covers all applicable requirements
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q5, Q6"
relationships:
  - type: related_to
    target_id: concept.pci-pin-hsm-certification
status: active
```

---

### PCI PIN: HSM Certification Requirements

```yaml
id: concept.pci-pin-hsm-certification
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 1 — HSM Must Be FIPS 140-2 Level 3 or PCI Approved
summary: >
  HSMs used for PIN acquiring must be either PCI approved or FIPS 140-2 Level 3 or higher
  certified. The FIPS certificate scope must include: (1) the hardware where all cryptographic
  processes execute and secret data is stored; (2) the firmware required to load vendor-provided
  software components securely; and (3) for new deployments after 1 July 2020, the tamper-
  responsive boundaries within which PIN translation occurs. APC holds FIPS 140-2 Level 3
  and PCI PTS HSM V3 certifications.
domain:
  - compliance
  - hsm
attributes:
  required_certification: "FIPS 140-2 Level 3 or PCI Approved"
  fips_scope_must_cover:
    - hardware executing cryptographic processes and storing secret data
    - firmware for loading vendor software securely
    - tamper-responsive boundaries for PIN translation (new deployments post 2020-07-01)
  apc_status: "meets requirement — FIPS 140-2 Level 3 + PCI PTS HSM V3"
constraints:
  - HSMs on NIST CMVP Historical Validation List cannot be used for new deployments after December 2019
  - If applying a vendor firmware patch, entity must obtain documentation confirming the update was submitted for NIST/PCI evaluation
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q9, Q10, Q13, Q14"
relationships:
  - type: related_to
    target_id: concept.pci-pin-cloud-hsm-compliance
status: active
```

---

### PCI PIN: TDES Wrapping AES Keys Is Treated as Cleartext Injection

```yaml
id: concept.pci-pin-tdes-aes-wrap-cleartext
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 10 / Requirement 1 — TDES Wrap of AES Key = Cleartext Injection
summary: >
  TDES keys are significantly weaker than AES keys. Using a TDES key to encrypt an AES key
  for conveyance is treated by PCI PIN as equivalent to cleartext key injection. It is
  permitted only via direct cable connection (not over a network) and requires a secure room
  as defined in Requirement 32-9. Key-encipherment keys must be of equal or greater strength
  than the keys they protect for any network transport. AES keys encrypted with 2048-bit RSA
  for transport is the permitted exception (RSA 2048 provides ~112-bit strength, sufficient for
  AES-128 but not for AES-256 — for AES-256, Diffie-Hellman or Elliptic Curve must be used).
domain:
  - key_management
  - compliance
  - cryptography
attributes:
  tdes_wrapping_aes_treatment: "cleartext injection"
  tdes_wrapping_aes_allowed_via: "direct cable only, not network, requires secure room"
  rsa_2048_wrapping_aes_128: "permitted"
  rsa_2048_wrapping_aes_256: "NOT permitted — use DH or ECDH"
  key_strength_rule: "encipherment key must be >= strength of protected key for network transport"
constraints:
  - Never transport AES keys under TDES over a network — treat as cleartext breach
  - APC TR-31 import uses RSA-2048 or RSA-3072 to wrap the key block — compliant for AES-128 and AES-256
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q1, Q3, Q4, Q20"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
status: active
```

---

### PCI PIN: Acquiring HSMs Must Not Output Cleartext PINs

```yaml
id: concept.pci-pin-acquiring-hsm-no-cleartext-pin
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 29 — Acquiring HSMs Must Disable Cleartext PIN Output
summary: >
  All commands and configuration options associated with outputting cleartext PINs must be
  disabled or removed from HSMs used for acquiring functions. HSMs temporarily used for PIN
  issuance may be reconfigured, but must use a separate key hierarchy (a different MFK).
  APC enforces this by design — it is a managed service scoped to acquirer use cases and
  does not expose cleartext PIN output commands.
domain:
  - compliance
  - hsm
  - pin_processing
constraints:
  - APC does not provide cleartext PIN output — compliant by design
  - If using a shared HSM for both issuing and acquiring, a separate MFK hierarchy is required for each role
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q40 (Req 29), Q39 (Req 23)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-hsm-certification
status: active
```

---

### PCI PIN: Deriving Initial DUKPT Keys from BDK Counts as Key Generation

```yaml
id: concept.pci-pin-dukpt-initial-key-is-key-generation
entity_type: compliance_rule
canonical_name: PCI PIN Normative Annex B — BDK-to-Initial-DUKPT Derivation Is Key Generation
summary: >
  When a Key Injection Facility (KIF) uses a BDK to derive initial DUKPT keys for injection
  into POI devices, that derivation counts as key generation under PCI PIN (per ISO 11568,
  repeatable key generation by key derivation). This means the KIF must meet all PCI PIN
  requirements for key-generation facilities. Initial DUKPT keys must be conveyed to POI
  devices encrypted under a key of equal or greater strength (TR-31 key block).
domain:
  - key_management
  - compliance
constraints:
  - KIF performing BDK-to-IPEK derivation must comply with PCI PIN key-generation facility requirements
  - IPEK/initial key transport to POI must use equal-or-greater-strength wrapping key
  - APC does not export IPEKs in cleartext; export is under a TR-31 KEK or asymmetric wrap
references:
  - "PCI PTS PIN Technical FAQs v3 June 2021, Q57 (Annex B), Q58 (Annex B)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
status: active
```

---

### PCI PIN: Fixed Key TDES Is Banned; ISO Format 4 Is Mandated

```yaml
id: concept.pci-pin-tdes-sunset-and-format4-mandate
entity_type: compliance_rule
canonical_name: PCI PIN v3 — Fixed Key TDES Banned 2023; ISO Format 4 Encouraged, Mandate Dates Suspended
summary: >
  PCI PIN v3.0 (August 2018) banned fixed key TDES for PIN encryption effective 1 January 2023
  (both POI devices and host-to-host). This ban is confirmed and in force (PCI PIN §8.2 FAQ).
  NIST SP 800-57 Rev. 5 independently disallowed 3-key TDEA after 2023. Fixed key AES PIN
  encryption is unaffected.
  ISO Format 4 mandate dates (decryption by 2023-01-01, encryption by 2025-01-01) were set in
  v3.0 but SUSPENDED by PCI PIN v3.1 (March 2021) while PCI SSC re-evaluates. As of this KB
  entry, no mandatory Format 4 effective dates are in force. Migration to Format 4 is strongly
  encouraged as the only format supporting AES, but not yet required by a fixed deadline.
  PCI PIN v3 also added ANSI X9.24-3 (AES DUKPT) and ANSI TR-34 as normative references.
domain:
  - compliance
  - pin_processing
  - cryptography
attributes:
  tdes_fixed_key_sunset:
    poi_devices: "2023-01-01 — fixed key TDES PIN encryption in POI devices is disallowed (confirmed)"
    host_to_host: "2023-01-01 — fixed key TDES PIN encryption in host-to-host connections is disallowed (confirmed)"
    nist_status: "NIST SP 800-57 Rev.5 disallows 3-key TDEA after 2023 independently of PCI"
  double_length_tdes_dukpt_exemption: >
    Double-length (2-key) TDES is disallowed by NIST since 2015, but PCI has NOT adopted that
    ban for DUKPT use cases: double-length TDES DUKPT (unique key per transaction) remains
    PCI-acceptable per PCI PIN and PTS because the unique-key property preserves effective
    security. PCI diverges from NIST here for payment-specific reasons. EXCEPTION: CPoC and
    SPoC programs require AES-128 minimum and do not accept the double-length TDES DUKPT
    exemption. (Source: SRC expert opinion letter to ep2, October 2020.)
  iso_format_4_mandate:
    status: "SUSPENDED — PCI PIN v3.1 (March 2021) suspended the v3.0 sunrise dates pending re-evaluation"
    original_v30_dates: "decryption 2023-01-01, encryption 2025-01-01 (never took effect)"
    poi_v5_plus: "POI devices approved to PCI PTS POI v5+ are required to support Format 4"
  normative_references_added_in_v3: ["ANSI X9.24-3 (AES DUKPT)", "ANSI TR-34"]
  kcv_requirement: "KCV optional for TDEA keys, mandatory for AES keys"
  iso8583_transport: >
    Original ISO 8583 Field 52 is 64-bit only — too small for Format 4 (128-bit).
    ISO 13492 adds Fields 110, 111, and 50 for AES support in ISO 8583.
    ISO 20022 (ATICA) supports AES natively via variable-length fields.
  format4_structure_summary: >
    Two 128-bit fields: PIN field (C=0100, N=PIN length, P=PIN digits, F=fill 0xA, R=64 random bits)
    and PAN field (M=control for PAN 12-19 digits, A=PAN digits, zero-padded).
    Encryption: AES(PIN field) XOR PAN field, then AES again. Requires AES (128-bit block cipher).
    Both encrypt and decrypt must occur within an SCD/HSM.
  format4_prevents_replay: "Random bits in lower 64 bits of PIN field make each block unique except by chance"
  format_translation_restrictions: >
    Format 0→4: Permitted. Format 1→4: Permitted. Format 2→4: NOT Permitted.
    Format 3→4: Permitted. Standard formats (0-4) must not be translated to non-standard formats.
    PAN must not change during translation between formats that both include the PAN.
constraints:
  - Fixed key TDES for PIN is banned — compliant deployments must use DUKPT (TDES or AES)
  - Double-length TDES DUKPT remains acceptable under PCI PIN/PTS for unique-key-per-transaction deployments
  - CPoC and SPoC programs require AES-128 minimum — double-length TDES DUKPT is NOT acceptable there
  - ISO Format 4 has no mandatory effective date as of 2026 — but is the only format supporting AES
  - AES DUKPT (X9.24-3) is a PCI PIN normative reference — use for all new deployments
  - APC supports ISO Format 4 (TR31_P0_PIN_ENCRYPTION_KEY with AES) — use this for new deployments
  - Format 4 → Format 0/3 translation at HSM is a valid interim strategy while upstream catches up
  - Tokens used as PAN in Format 4 blocks must preserve PAN format (Luhn, length)
  - Cleartext key injection ban (Req 32-9 normative): entities injecting into POI v5+ devices on behalf of others — 1 January 2024; processors injecting into their own devices — 1 January 2026
  - "Strong Cryptography" is defined only in the PCI DSS Glossary; PCI DSS itself has no
    cryptographic algorithm requirements — algorithm mandates come from PCI PIN, PCI PTS,
    PCI P2PE, PCI CPoC, and PCI SPoC
references:
  - "PCI PIN Security Requirements Modifications Summary of Changes v2.0 to v3.0, August 2018"
  - "PCI PTS PIN Technical FAQs v3 June 2021, §8.2"
  - "PCI Information Supplement: Implementing ISO Format 4 PIN Blocks, September 2021, §4 (suspension notice)"
  - "SRC Security Research & Consulting GmbH expert opinion letter to Technical Cooperation ep2, October 2020 (double-length TDES DUKPT exemption; CPoC/SPoC AES requirement; Strong Cryptography scope)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: algorithm.dukpt
  - type: related_to
    target_id: rule.apc-iso-format4-required
status: active
```

---

### PCI PIN: KCV Method Rule — AES Must Use CMAC

```yaml
id: concept.pci-pin-kcv-method-rule
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 15-1 — KCV Algorithm and Bit-Length Rules
summary: >
  PCI PIN Req 15-1 mandates specific KCV methods per algorithm. AES keys MUST use
  CMAC-based KCV; the ECB-zeros method (encrypt a block of zeros, take leftmost bytes)
  is prohibited for AES. TDEA keys may use either ECB-zeros or CMAC. KCV bit lengths
  are capped: AES KCV is the leftmost ≤40 bits (10 hex digits) of the AES-CMAC output;
  TDEA KCV is the leftmost ≤24 bits (6 hex digits) of the ECB-zeros or CMAC output.
  This requirement is enforced in APC — the API rejects ANSI_X9_24 KCV method for AES keys.
domain:
  - key_management
  - compliance
  - cryptography
attributes:
  aes_kcv_method: "CMAC only — ECB-zeros is prohibited"
  aes_kcv_length: "leftmost ≤40 bits (up to 10 hex digits) of AES-CMAC result"
  tdea_kcv_method: "ECB-zeros OR CMAC — both acceptable"
  tdea_kcv_length: "leftmost ≤24 bits (up to 6 hex digits) of ECB-zeros or CMAC result"
  apc_enforcement: "APC API enforces CMAC for AES; create_key rejects ANSI_X9_24 for AES keys"
constraints:
  - Never use ECB-zeros KCV for AES keys — PCI PIN violation
  - AES KCV value must be 10 hex digits (5 bytes) or fewer — never the full 32-byte AES-CMAC output
  - TDEA KCV value must be 6 hex digits (3 bytes) or fewer — "KCV" in most HSM UIs is the first 3 bytes
  - When comparing KCVs between two parties, the truncation length must be agreed in advance
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §15-1"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: concept.pci-pin-key-strength-hierarchy
status: active
```

---

### PCI PIN: Key Strength Hierarchy — Annex C Equivalence Table

```yaml
id: concept.pci-pin-key-strength-hierarchy
entity_type: compliance_rule
canonical_name: PCI PIN Annex C — Key Strength Equivalence and Encipherment Hierarchy Rules
summary: >
  PCI PIN Annex C defines minimum key sizes by bits-of-security equivalence and the rule
  that an enciphering (wrapping) key must be of equal or greater strength than the key it
  protects. Violating this hierarchy (e.g., using TDEA to wrap AES) is treated as cleartext
  injection for network transport. The table governs all key encipherment decisions including
  TR-31 KBPK selection, RSA key transport wrap, and TR-34 KDH key pairs.
domain:
  - key_management
  - compliance
  - cryptography
attributes:
  bits_of_security_table:
    80_bits:   ["2-key TDEA (112-bit key, effective 80-bit security)", "RSA-1024 (prohibited)"]
    112_bits:  ["3-key TDEA (168-bit key)", "RSA-2048", "DH-2048", "EC-224 (P-224)"]
    128_bits:  ["AES-128", "RSA-3072", "DH-3072", "EC-256 (P-256)"]
    192_bits:  ["AES-192", "RSA-7680", "EC-384 (P-384)"]
    256_bits:  ["AES-256", "RSA-15360", "EC-512 (P-512)"]
  key_encipherment_rule: >
    The enciphering key must have bits-of-security >= the bits-of-security of the key
    it protects. Applies to all key transport and storage scenarios.
  critical_implications:
    tdea_cannot_protect_aes: >
      3-key TDEA (112-bit security) cannot protect AES-128 (128-bit security) over a network.
      Doing so is treated as cleartext injection per PCI PIN Req 10-1.
    rsa_2048_can_protect_aes_128: >
      RSA-2048 (112-bit security) equals 3-key TDEA strength — it CAN protect AES-128 only
      if both are considered equivalent (per older interpretations). Strict Annex C reading:
      RSA-2048 = 112 bits < AES-128 = 128 bits, so RSA-3072 is required for AES-128.
      APC TR-31 import supports RSA-3072 which covers both AES-128 and AES-256 wrapping.
    rsa_2048_cannot_protect_aes_256: >
      RSA-2048 (112-bit security) cannot wrap AES-256 (256-bit security). Use RSA-3072+ or
      ECDH (P-256+) for AES-256 key transport.
    two_key_tdea_prohibited: >
      2-key TDEA provides only 80-bit security — below the minimum for any key encipherment
      since it fails to protect even 3-key TDEA (112-bit). Prohibited as encipherment key.
constraints:
  - Always use RSA-3072 or EC-256+ for wrapping AES keys in TR-31 or TR-34 flows
  - TDEA KBPK (TR-31 key-block protection key) must be 3-key TDEA to protect 3-key TDEA payloads
  - TDEA KBPK cannot be used to protect AES key payloads — use AES-128+ KBPK for AES keys
  - APC import flow uses RSA-3072 OAEP by default — sufficient for all AES key sizes
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 Annex C"
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §10-1"
relationships:
  - type: related_to
    target_id: concept.pci-pin-tdes-aes-wrap-cleartext
  - type: related_to
    target_id: concept.pci-pin-kcv-method-rule
  - type: related_to
    target_id: algorithm.tr31
status: active
```

---

### PCI PIN: PIN Block Translation Matrix (Req 3-3)

```yaml
id: concept.pci-pin-translation-matrix
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 3-3 — Permitted PIN Block Format Translation Pairs
summary: >
  PCI PIN Req 3-3 defines which PIN block format translations are permitted. PAN must be
  identical in both the incoming and outgoing PIN block for any translation that includes
  PAN in both formats. Standard ISO 9564 formats (0–4) must never be translated to
  non-standard or vendor-specific formats. APC enforces this: the translate_pin_data API
  rejects PAN mismatches and disallows unsupported format pairs.
domain:
  - pin_processing
  - compliance
attributes:
  permitted_translations:
    format_0_to_0: "Permitted — same format retranslation (key change or network handoff)"
    format_0_to_3: "Permitted"
    format_0_to_4: "Permitted (recommended upgrade path)"
    format_3_to_3: "Permitted"
    format_3_to_4: "Permitted"
    format_4_to_0: "Permitted (for backward compatibility with downstream systems)"
    format_4_to_3: "Permitted"
    format_1_to_4: "Permitted"
  prohibited_translations:
    format_2_to_4: "NOT Permitted — Format 2 is chip-internal only, must not appear in network flow"
    standard_to_nonstandard: "NOT Permitted — standard formats must not be translated to non-standard/vendor formats"
  pan_rule: >
    For any translation where both the incoming and outgoing format include the PAN
    (Formats 0, 3, 4), the PAN must be identical. APC enforces this at the API level —
    IncomingTranslationAttributes.PanBlockValue and OutgoingTranslationAttributes.PanBlockValue
    must carry the same PAN; the service rejects mismatches.
  aes_pin_block_note: >
    ISO Format 4 is the only format that supports AES encryption. Format 0 and Format 3
    are TDES (64-bit block). Translating Format 4 → Format 0/3 downgrades to TDES for
    backward-compatible downstream delivery; the incoming key must be an AES key (P0),
    the outgoing key must be a TDES key (P0).
constraints:
  - APC translate_pin_data enforces PAN identity — do not pass different PANs
  - Format 2 (chip-internal) must never leave an ICC; reject any network PIN block claiming Format 2
  - Translations to/from non-standard formats are prohibited — only use ISO 9564 formats 0–4
  - When translating Format 4 → Format 0 for downstream, document this as a legacy constraint
    and plan migration to Format 4 end-to-end
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §3-3"
  - "ISO 9564-1:2017 §9 (PIN block formats 0–4)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-tdes-sunset-and-format4-mandate
  - type: related_to
    target_id: format.pin-block-format-0
  - type: related_to
    target_id: format.pin-block-format-4
status: active
```

---

### PCI PIN: Cleartext Injection Ban Dates (Req 32-9)

```yaml
id: concept.pci-pin-cleartext-injection-ban
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 32-9 — Cleartext Key Injection Ban Effective Dates
summary: >
  PCI PIN Req 32-9 requires key injection into POI devices to occur only within a
  physically secure environment (secure room). The normative text establishes specific
  ban dates for cleartext key injection outside a secure room, phased by entity type.
  Entities must have migrated to secure remote key injection (RKI) or a secure room
  by these dates.
domain:
  - key_management
  - compliance
attributes:
  cleartext_injection_ban_dates:
    third_party_injectors: >
      1 January 2024 — entities injecting keys into POI devices on behalf of other parties
      (e.g., third-party KIFs, ESOs, injection bureaus) must cease cleartext injection
      outside a secure room for POI v5+ devices by this date.
    own_device_processors: >
      1 January 2026 — processors and acquirers injecting keys into their own POI devices
      must cease cleartext injection outside a secure room by this date.
  secure_room_exception: >
    Cleartext key injection remains permissible inside a physically secure environment
    (secure room) meeting all Annex B controls: perimeter integrity, dual-entry control,
    CCTV, access log, clean-desk policy. The secure room exception does not apply to
    injection performed over a network connection.
  rki_alternatives:
    - "TR-34 (ANSI X9.143) asymmetric remote key injection — preferred for new deployments"
    - "DUKPT — BDK stored in APC; only derived keys injected; avoids cleartext injection entirely"
constraints:
  - After 2024-01-01, third-party KIFs may not inject cleartext keys into POI v5+ devices outside a secure room
  - After 2026-01-01, no entity may inject cleartext keys into POI devices outside a secure room
  - APC BDK-based DUKPT avoids this constraint entirely — derived keys (IPEKs) are injected, not BDKs
  - APC TR-34 export (get_parameters_for_export) supports secure RKI as the modern alternative
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §32-9 and Annex B"
relationships:
  - type: related_to
    target_id: concept.pci-pin-dukpt-initial-key-is-key-generation
  - type: related_to
    target_id: concept.pci-pin-cloud-hsm-compliance
status: active
```

---

### PCI PIN: Production/Test Key Separation (Req 19-4)

```yaml
id: concept.pci-pin-prod-test-separation
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 19-4 — Keys Must Never Be Shared Between Production and Test Systems
summary: >
  PCI PIN Req 19-4 prohibits sharing cryptographic keys between production and test/development
  systems in either direction. A key used in production must never be present in a test system,
  and vice versa. For logically partitioned HSMs (including managed services), if any partition
  is used for testing the entire logical configuration — including all connected computing
  platforms and networking equipment — must be treated and managed as production.
domain:
  - key_management
  - compliance
attributes:
  rule: "Zero overlap between production and test key material"
  logical_partition_note: >
    If a physical or logical HSM partition is used for both production and test purposes,
    the entire configuration (all connected platforms, networks) must be managed as production.
    This effectively prohibits mixed-use HSM configurations.
  apc_implication: >
    APC accounts used for development/testing must use entirely separate AWS accounts
    or at minimum separate key hierarchies with no key material reuse. There is no
    APC-native "test mode" — the service is always production-equivalent.
  verification_method: >
    Assessors verify using KCV/hash/fingerprint comparison between production and test
    keys for higher-level keys (MFKs, KEKs shared with network nodes, BDKs).
constraints:
  - Never import a production BDK, ZMK, or KEK into a test/development APC account or region
  - Never use test keys generated in a dev environment in a production APC deployment
  - APC keys tagged with environment=prod and environment=test must have no shared key material
  - Use separate APC key aliases per environment — do not reuse alias names across prod/test accounts
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §19-4"
relationships:
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
  - type: related_to
    target_id: concept.pci-pin-cloud-hsm-compliance
status: active
```

---

### PCI PIN: Key Uniqueness Per Organizational Link (Req 17)

```yaml
id: concept.pci-pin-key-uniqueness-per-link
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 17 — Unique Keys Per Organizational Link (ZPK/KEK Uniqueness)
summary: >
  PCI PIN Req 17 requires that unique, secret cryptographic keys are in use for each
  identifiable link between host computer systems between two organizations or between
  logically separate systems within the same organization. A ZPK (Zone PIN Key) or KEK
  shared between two parties must be unique to that pair — it must not be given to any
  other organization or system. Key uniqueness must be verified via KCV at establishment.
domain:
  - key_management
  - compliance
attributes:
  uniqueness_scope: >
    Each bilateral link between organizations (or logically separate systems) must use a
    distinct key. A single ZPK must not be reused across multiple network counterparties.
  kcv_verification: >
    Key uniqueness is verified by generating KCVs for KEKs and comparing them between
    the two organizations. For remote key establishment (TR-34, ECDH), public key
    fingerprints or hash values are examined instead.
  known_default_keys: >
    Assessors compare KCV values against known or default keys to verify that default
    factory keys are not in use in production links.
  apc_implication: >
    Each APC-managed ZPK alias should correspond to exactly one bilateral network
    connection. Never share a ZPK across multiple acquirer–network relationships.
    Use separate APC key aliases (e.g., alias/zpk-visanet, alias/zpk-mastercard) per link.
constraints:
  - One ZPK (or KEK) per bilateral link — never share a zone key across multiple counterparties
  - KCV comparison between parties is required to prove uniqueness at key establishment
  - Default or factory keys must not be used in production — replace all vendor defaults before go-live
  - APC aliases must model network topology: one alias per bilateral key relationship
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §17 and §17-1"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: concept.pci-pin-kcv-method-rule
status: active
```

---

### PCI PIN: MFK Minimum Key Strength (Req 12-5)

```yaml
id: concept.pci-pin-mfk-minimum-key
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 12-5 — MFK (LMK) Must Be Double-Length TDEA or AES ≥128 bits
summary: >
  PCI PIN Req 12-5 sets the minimum key strength for the HSM Master File Key (MFK, also
  called Local Master Key / LMK in Thales terminology). The MFK must be at minimum double-
  length TDEA (112-bit effective security) or AES ≥128 bits. Single-DES MFKs and any MFK
  below this threshold are prohibited. APC manages its internal key hierarchy as a managed
  service — the MFK analog in APC is an AWS-managed root key; acquirers cannot access or
  configure it, but APC's FIPS 140-2 Level 3 certification demonstrates compliance.
domain:
  - key_management
  - compliance
  - hsm
attributes:
  mfk_minimum: "double-length TDEA (112-bit) or AES-128 minimum"
  mfk_prohibited: "single-DES MFK — absolute hard stop"
  lmk_synonym: "LMK (Local Master Key) = MFK — same concept, different vendor terminology (Thales uses LMK)"
  mfk_definition: >
    The MFK is a symmetric key used to encrypt other cryptographic keys that are stored
    outside the HSM. It is the root of the HSM's key hierarchy. All keys stored in the
    HSM's key database are wrapped under the MFK.
  mfk_variant_rule: >
    Per Req 23, MFK variants must not be used external to the logical configuration that
    houses the MFK. MFK variants used for local key storage cannot be used for key
    conveyance between platforms.
  apc_mfk_status: >
    APC does not expose the MFK concept to users. AWS manages equivalent root key
    material under FIPS 140-2 Level 3 controls. Acquirers do not need to configure or
    manage an MFK when using APC.
constraints:
  - On physical HSMs: do not use single-DES MFK or any MFK below double-length TDEA strength
  - APC satisfies this requirement by design — the HSM root key is AWS-managed and certified
  - When migrating from a physical HSM to APC, do not export or expose the legacy MFK
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §12-5"
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §23 (MFK variant restrictions)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-strength-hierarchy
  - type: related_to
    target_id: concept.pci-pin-hsm-certification
status: active
```

---

### PCI PIN: Key Compromise Response (Req 22)

```yaml
id: concept.pci-pin-key-compromise-response
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 22 — Key Compromise Response — Replace All Derived and Subordinate Keys
summary: >
  When a cryptographic key is known or suspected compromised, PCI PIN Req 22 mandates
  replacing that key plus ALL keys derived from it and ALL keys it has protected (encrypted).
  The replacement key must not be a variant or irreversible transformation of the compromised
  key. All affected parties sharing the key must be notified. For APC-managed keys, compromise
  response requires deleting the APC key and creating a new one with new key material —
  key rotation alone (same KMS key, new version) does not satisfy the PCI requirement.
domain:
  - key_management
  - compliance
attributes:
  trigger_events:
    - known compromise of a key component or share
    - key component packaging showing signs of tampering
    - key substitution or synchronization error patterns suggesting key swap
    - missing SCD or device where key was loaded
    - unauthorized access to system housing the key
  replacement_rule: >
    Replace the compromised key AND all keys encrypted under it AND all keys derived from it.
    The replacement key must not be a variant or irreversible transformation of the original.
  notification_requirement: >
    Organizations currently sharing or that have previously shared the key must be notified.
    Notification includes: identification of key personnel, damage assessment (possibly with
    outside consultants), and specific actions for system software/hardware, other encryption
    keys, and encrypted data.
  apc_compromise_response:
    step_1: "Call delete_key on the compromised APC key immediately"
    step_2: "Create a new APC key with fresh key material — do not re-import old material"
    step_3: "Replace all keys that were exported under the compromised KEK using a new KEK"
    step_4: "Replace all BDKs whose IPEKs were exported under the compromised key"
    step_5: "Notify all counterparties who shared a ZPK or KEK with the compromised entity"
    step_6: "Re-establish all bilateral key relationships using TR-34 or fresh TR-31 exchange"
constraints:
  - Replacement key must not be a variant of the compromised key
  - All derived keys (BDK → IPEK → session keys) must also be replaced
  - All keys encrypted by the compromised KEK must be treated as compromised
  - APC key deletion (delete_key) schedules destruction after a configurable delay — use stop_key_usage immediately on suspicion, delete after confirmation
  - Audit trail of compromise event must be retained
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §22 and §22-1 through §22-2"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-uniqueness-per-link
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
  - type: related_to
    target_id: concept.pci-pin-mfk-minimum-key
status: active
```

---

### PCI PIN: Dual Control and Split Knowledge (Req 6-1.2 / Req 21-2)

```yaml
id: concept.pci-pin-dual-control-split-knowledge
entity_type: compliance_rule
canonical_name: PCI PIN Requirements 6-1.2 and 21-2 — Dual Control and Split Knowledge for Key Operations
summary: >
  PCI PIN mandates dual control and split knowledge for all key-management operations.
  No single individual may know or reconstruct a complete cleartext key value; at least two
  trusted individuals must be simultaneously present for any operation on a key or its
  components. This applies to key generation, loading, backup, and destruction — not only
  to the physical ceremony but also to system-enforced access controls.
domain:
  - key_management
  - compliance
attributes:
  req_6_1_2_verbatim: >
    "Key-management operations must be performed by a minimum of two trusted individuals
    who are simultaneously present."
  req_21_2_verbatim: >
    "No single person shall have access to, knowledge of, or use of any keys or key
    components/shares enabling them to determine a key value (whether in the clear or
    encrypted under a known key) or to place a key of their own choosing into a system."
  applies_to:
    - key generation ceremonies
    - manual key loading (smart card custodians, ceremony officers)
    - key component entry on HSM consoles
    - backup key ceremonies
    - key destruction events
    - remote key distribution (TR-34 KDH ceremonies)
  system_enforcement:
    - HSM smart-card schemes (M-of-N) directly enforce split knowledge
    - Single-officer logon to HSM console is insufficient where dual control is required
    - Logging alone does not substitute for physical simultaneous presence
  apc_posture: >
    APC key material is never exposed in cleartext to any AWS operator (FIPS 140-2 Level 3
    boundary). The dual-control obligation shifts to the customer's key ceremony for importing
    key components or generating TR-31/TR-34 exchange keys. Use APC get_parameters_for_import
    with a split-knowledge ceremony for the transport KEK.
constraints:
  - Minimum two individuals simultaneously present for any key management operation
  - No single individual may know, derive, or reconstruct a complete cleartext key
  - Smart-card or split-component schemes must enforce M-of-N (M >= 2)
  - System roles must be segregated so no one operator can complete a key ceremony alone
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §6-1.2 (CO2 — key creation)"
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §21-2 (CO6 — key administration)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
  - type: related_to
    target_id: concept.pci-pin-key-compromise-response
status: active
```

---

### PCI PIN: Email Prohibition for Key Conveyance (Req 8-3)

```yaml
id: concept.pci-pin-email-key-prohibition
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 8-3 — Email Must Not Be Used for Key or Component Conveyance
summary: >
  PCI PIN Req 8-3 explicitly prohibits email as a channel for conveying secret or private
  keys and their components, even when the email itself is encrypted. The rationale is that
  email exposes key material to in-memory risks during composition/rendering, and corporate
  email systems are typically subject to administrator recovery, retention scanning, and
  backup policies that extend the exposure window.
domain:
  - key_management
  - compliance
attributes:
  req_8_3_verbatim: >
    "E-mail shall not be used for the conveyance of secret or private keys or their
    components/shares, even if encrypted."
  rationale:
    - "Email clients decrypt message content into addressable memory — key material is transiently cleartext on the workstation"
    - "Corporate email systems typically have administrator-accessible recovery and backup paths"
    - "S/MIME or PGP encryption protects channel but not in-memory exposure during composition or reading"
    - "Email retention policies and legal hold mechanisms extend exposure window beyond intended lifecycle"
  compliant_alternatives:
    - "Physical courier (sealed tamper-evident envelope) with chain-of-custody log"
    - "TR-34 remote key exchange using authenticated HSM-to-HSM channels"
    - "TR-31 Key Block delivered over a mutually authenticated TLS session separate from email"
    - "Smart card ceremony with M-of-N officer cards carried independently"
  apc_posture: >
    APC TR-34 import (get_parameters_for_import → import_key with KEY_CRYPTOGRAM) eliminates
    the email risk by using RSA-OAEP to wrap key material for an APC-controlled public key,
    ensuring the key never traverses email. All import traffic is over TLS to the APC endpoint.
constraints:
  - Email is prohibited regardless of whether the email content is encrypted
  - Prohibition covers keys, components/shares, and key-check values used to reconstruct a key
  - Covers both one-time and recurring key conveyance arrangements
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §8-3 (CO3 — key conveyance)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-component-channel-separation
  - type: related_to
    target_id: concept.pci-pin-key-block-requirements
status: active
```

---

### PCI PIN: Key Component Channel Separation (Req 8-1 Note)

```yaml
id: concept.pci-pin-component-channel-separation
entity_type: compliance_rule
canonical_name: PCI PIN Requirement 8-1 — Key Components Must Travel via Separate Communication Channels
summary: >
  PCI PIN Req 8-1 requires that the components or shares of a single key be sent via
  different communication channels. Sending components on different days using the same
  channel (e.g., same courier company, same network path) does NOT satisfy the requirement.
  The channels themselves must be independent so that compromise of one channel does not
  expose enough material to reconstruct the key.
domain:
  - key_management
  - compliance
attributes:
  req_8_1_note_verbatim: >
    "Components/shares of encryption keys must be conveyed using different communication
    channels. It is not sufficient to send key components/shares for a specific key on
    different days using the same communication channel."
  what_counts_as_different_channels:
    - "Different courier companies carrying different components independently"
    - "One component by physical courier, another by TR-34 electronic channel"
    - "One component on smart card hand-carried by officer A, another by officer B via a separate carrier"
  what_does_not_qualify:
    - "Component 1 on Monday via FedEx, Component 2 on Tuesday via FedEx — same channel"
    - "Both components sent over the same TLS network path on different days"
    - "Both components in separate emails over the same email system (also prohibited by Req 8-3)"
  relationship_to_split_knowledge:
    - "Channel separation is the transport enforcement of split knowledge (Req 6-1.2 / 21-2)"
    - "Even if custodians are different, using the same channel undermines the independence goal"
  apc_posture: >
    APC TR-34 import eliminates multi-component channel risk by using a single cryptographic
    ceremony where the customer generates the transport key pair independently of APC's
    certification authority. The split-knowledge obligation is satisfied within the customer's
    HSM ceremony, not via multi-leg transport.
constraints:
  - Different channels required — not just different days on the same channel
  - Channel separation applies per-key: each key's components must use distinct channels
  - Combination of physical courier and electronic channel (TR-34) satisfies the requirement
references:
  - "PCI PIN Security Requirements and Testing Procedures v3.1 §8-1 and associated Note (CO3 — key conveyance)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-email-key-prohibition
  - type: related_to
    target_id: concept.pci-pin-dual-control-split-knowledge
status: active
```

---

## PCI P2PE Standard v3.2 — Acquirer-Relevant Rules

### PCI P2PE: Solution Architecture and APC Applicability

```yaml
id: concept.pci-p2pe-architecture
entity_type: compliance_rule
canonical_name: PCI P2PE v3.2 — Solution Architecture, Domain Structure, and APC Applicability
summary: >
  PCI P2PE v3.2 (June 2025) governs point-to-point encryption of account data from the moment
  of card capture at a POI through decryption at a secure decryption environment.  The standard
  defines 5 Domains plus Appendix A (merchant-managed).  Domain 4 covers decryption environments
  (HSMs); Domain 5 mirrors PCI PIN's 7 Control Objectives but scoped to account-data encryption
  keys rather than PIN keys.  AWS Payment Cryptography satisfies Domain 4 and Domain 5 HSM
  requirements as a FIPS 140-2 Level 3 / PCI PTS HSM V3-certified managed service.
  Decryption solutions come in two variants: Hardware (all key management AND decryption inside
  an HSM/SCD) and Hybrid (key management in HSM, decryption performed in a non-SCD Host System).
  Merchant-managed P2PE solutions are restricted to Hardware decryption only (Appendix A) and
  are NOT listed on the PCI SSC website.
domain:
  - compliance
  - key_management
  - cryptography
attributes:
  standard: "PCI Point-to-Point Encryption (P2PE) Standard v3.2, June 2025"
  domains:
    domain_1: "P2PE encryption environment (POI device, SRED, account-data capture)"
    domain_2: "P2PE applications (POI and decryption)"
    domain_3: "P2PE solution management"
    domain_4: "Decryption environments — HSM/SCD requirement; APC satisfies this"
    domain_5: "P2PE device management (mirroring PCI PIN COs 1–7 for account-data keys)"
    appendix_a: "Merchant-managed solutions — hardware decryption only, not on PCI SSC list"
  decryption_variants:
    hardware: "All key management AND decryption performed in an HSM/SCD"
    hybrid: >
      Key management in an HSM; decryption performed in a non-SCD Host System.
      Permitted for P2PE solution providers but NOT for merchant-managed solutions.
  sred: >
    Secure Reading and Exchange of Data — required PTS POI function that encrypts account
    data at the point of capture inside the POI device.
  apc_coverage:
    domain_4: "APC is a PCI PTS HSM V3-certified managed HSM — satisfies decryption environment requirements"
    domain_5: "APC key management APIs satisfy all Domain 5 Control Objective requirements"
    merchant_managed_note: >
      APC can serve as the key-management HSM for merchant-managed solutions but the decryption
      operation must itself occur inside an HSM (hardware path); hybrid is prohibited.
constraints:
  - Merchant-managed P2PE requires hardware decryption only; hybrid is explicitly prohibited (Appendix A)
  - SRED is required for all P2PE account-data capture at POI
  - P2PE solution providers must be listed on PCI SSC website; merchant-managed solutions are not listed
references:
  - "PCI P2PE Standard v3.2 §Domain structure overview, §Domain 4, §Domain 5, §Appendix A"
relationships:
  - type: related_to
    target_id: concept.pci-p2pe-hybrid-ddk-controls
  - type: related_to
    target_id: concept.pci-pin-cloud-hsm-compliance
status: active
```

---

### PCI P2PE: Mandatory Algorithm and Key-Size Requirements (Annex C)

```yaml
id: concept.pci-p2pe-account-data-algorithms
entity_type: compliance_rule
canonical_name: PCI P2PE v3.2 Normative Annex C — Mandatory Algorithms and Minimum Key Sizes
summary: >
  PCI P2PE Normative Annex C defines the minimum key sizes and approved algorithm families for
  all P2PE cryptographic keys.  The equivalence table is identical to PCI PIN Annex C.  AES ≥128
  bits or TDEA ≥168 bits are the baseline minimums.  Two special exceptions apply: (1) PTS POI
  v3.x+ devices may use 2-key TDEA ONLY when combined with DUKPT/UKPT per ISO 11568; (2) a
  2048-bit RSA key may transport an AES-128 key for remote key distribution (exception to the
  general rule that a KEK must be at least as strong as the key it protects).  SHA-1 is
  prohibited for digital signatures on PTS POI v3+; SHA-2 or SHA-3 required.
domain:
  - compliance
  - cryptography
  - key_management
attributes:
  minimum_key_sizes:
    TDEA: "168 bits (triple-length)"
    AES: "128 bits minimum (AES-128, AES-192, or AES-256)"
    RSA: "2048 bits minimum"
    ECC: "224 bits minimum"
    FFC: "2048/224 bits minimum"
  equivalence_table:
    "112 bits": "Triple-TDEA / RSA-2048 / ECC-224 / FFC-2048+224"
    "128 bits": "AES-128 / RSA-3072 / ECC-256 / FFC-3072+256"
    "192 bits": "AES-192 / RSA-7680 / ECC-384 / FFC-7680+384"
    "256 bits": "AES-256 / RSA-15360 / ECC-512 / FFC-15360+512"
  exceptions:
    two_key_tdea: >
      Footnote 5: PTS POI v3.x+ devices may use 2-key TDEA (double-length BDK) ONLY when
      combined with DUKPT or UKPT per ISO 11568. This is the ONLY permitted use of 2-key TDEA.
    rsa_2048_aes_128: >
      Footnote 6: A 2048-bit RSA key may be used to transport an AES-128 symmetric key for
      remote key distribution. This is an explicit exception to the general KEK ≥ protected-key
      strength rule. RSA-2048 is 112-bit equivalent but may wrap AES-128 (128-bit) in this
      specific remote key distribution context.
  hash_requirements:
    poi_v3_plus: "SHA-1 prohibited for digital signatures; use SHA-2 or SHA-3"
    legacy_poi: "SHA-1 permitted on POI versions below v3"
  cryptoperiod_management: >
    All P2PE keys must have defined cryptoperiods managed per NIST SP800-57.
    Full key documentation required including purpose, algorithm, length, and cryptoperiod.
constraints:
  - TDEA minimum is 168-bit (triple-length); 128-bit (double-length) 2-key TDEA only with DUKPT on POI v3+
  - AES-128 is the absolute minimum; no AES-64 or non-standard variants
  - SHA-1 prohibited for digital signatures on POI v3+ devices
  - Cryptoperiods must be defined and enforced for all keys (NIST SP800-57)
references:
  - "PCI P2PE Standard v3.2 Normative Annex C (pages 244-246), June 2025"
  - "NIST SP800-57 Part 1 Rev 5 — Recommendation for Key Management"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-strength-hierarchy
  - type: related_to
    target_id: concept.pci-pin-tdes-aes-wrap-cleartext
  - type: related_to
    target_id: concept.pci-p2pe-kek-transport-prohibition
status: active
```

---

### PCI P2PE: POI Key Uniqueness and BDK Loading Prohibition (Req 20)

```yaml
id: concept.pci-p2pe-poi-key-uniqueness
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 20 — All POI Keys Must Be Unique Per Device; BDKs Never Loaded to POI
summary: >
  PCI P2PE Req 20-1 mandates that ALL cryptographic keys loaded into or generated for a POI
  device must be unique to that specific device.  This includes not just encryption/decryption
  keys but also KEKs, firmware authentication keys, and any other keys resident on the POI.
  Req 20-3 explicitly prohibits loading BDKs onto any PTS POI device — the BDK must remain
  in the secure decryption environment (HSM); only derived IPEK or session keys are present
  in the POI.  Req 20-5 requires separate BDKs per terminal type when terminal IDs can be
  duplicated across types.
domain:
  - compliance
  - key_management
attributes:
  req_20_1: >
    ALL keys in a PTS POI device must be unique per device. This is broader than DUKPT
    session-key uniqueness — it extends to KEKs used for remote key injection, firmware
    authentication keys, and any other key loaded to the POI.
  req_20_3: >
    BDKs must NEVER be loaded to PTS POI devices. The BDK resides only in the secure
    decryption environment (HSM). POI devices receive only derived keys (IPEKs or session
    keys), not the BDK from which they were derived.
  req_20_5: >
    When terminal IDs can be duplicated across different terminal types, separate BDKs
    must be used per terminal type to prevent key collisions.
  apc_application: >
    APC stores the BDK and performs DUKPT key derivation on-demand. The BDK never leaves
    APC in cleartext. IPEKs can be exported (encrypted under KEK) for loading to POI, but
    the BDK itself must not be exported for POI loading.
constraints:
  - Every key on every POI device must be device-unique (not shared across devices)
  - BDK must never be present on a POI device in any form
  - Separate BDKs required when terminal IDs can collide across terminal types
  - Firmware authentication keys are in scope for per-device uniqueness (same as transaction keys)
references:
  - "PCI P2PE Standard v3.2 §Req 20-1, §Req 20-3, §Req 20-5 (pages 171-176)"
relationships:
  - type: related_to
    target_id: concept.pci-p2pe-bdk-segmentation
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
  - type: related_to
    target_id: concept.pci-pin-dukpt-initial-key-is-key-generation
status: active
```

---

### PCI P2PE: BDK Segmentation for Multi-Acquirer Processors (Req 20-4)

```yaml
id: concept.pci-p2pe-bdk-segmentation
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 20-4 — BDK Segmentation Required Per Financial Institution
summary: >
  PCI P2PE Req 20-4 requires processors or acquirers operating on behalf of multiple financial
  institutions to maintain separate, distinct BDKs for each financial institution.  A BDK
  shared across financial institutions would allow transactions from one institution's terminals
  to be decrypted using another institution's key material — a clear security boundary violation.
  This is the P2PE normative mirror of PCI PIN Req 7-4.
domain:
  - compliance
  - key_management
attributes:
  requirement: >
    Processors/acquirers with multiple financial institution clients must use a separate BDK
    per financial institution. BDKs must not be shared across institutional boundaries.
  rationale: >
    Shared BDKs across institutions create mutual exposure: a compromise or audit event at
    one institution affects all institutions sharing that BDK.  Segmentation limits blast
    radius and supports independent key lifecycle management per institution.
  apc_implementation: >
    Create separate APC BDK keys tagged by financial institution (e.g., alias:
    bdk-institution-A, bdk-institution-B). Access policies on each key should restrict
    usage to the relevant institution's processing pipelines.
  multi_acquirer_scope: >
    Applies to any entity acting as a processor or acquirer for two or more financial
    institutions, even if those institutions use the same terminal estate.
constraints:
  - One BDK per financial institution — no sharing across institutional boundaries
  - Separate key aliases, policies, and audit trails per institution in APC
  - Applies even when institutions share the same physical terminal infrastructure
references:
  - "PCI P2PE Standard v3.2 §Req 20-4 (pages 173-174)"
  - "PCI PIN Security Requirements v3.1 §Req 7-4 (mirror requirement)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-bdk-segmentation
  - type: related_to
    target_id: concept.pci-p2pe-poi-key-uniqueness
status: active
```

---

### PCI P2PE: Hybrid DDK Controls — Software Key Management Exception (Req 5H)

```yaml
id: concept.pci-p2pe-hybrid-ddk-controls
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 5H — DDK Is the Only Software-Manageable P2PE Key; Strict Usage Controls Apply
summary: >
  In P2PE hybrid solutions, the Data Decryption Key (DDK) is the ONLY P2PE key that may be
  managed in software on a Host System (non-SCD).  All other P2PE keys must reside in and be
  managed by an HSM/SCD.  DDKs must have defined cryptoperiod limits (maximum transaction
  count AND/OR maximum time duration, e.g., "1024 transactions or 24 hours, whichever occurs
  first") OR be unique per transaction.  DDKs must be erased from host volatile memory via an
  irrecoverable mechanism validated by forensic testing.  The transport key that delivers the
  DDK from the HSM to the Host System must be unique per Host System, single-purpose, and
  at least as strong as the DDK it protects.  Hybrid decryption is NOT permitted for
  merchant-managed P2PE solutions (Appendix A); those require hardware decryption only.
domain:
  - compliance
  - key_management
  - cryptography
attributes:
  ddk_definition: >
    Data Decryption Key — the symmetric key used to decrypt account data in a P2PE hybrid
    solution. It is the only P2PE key that may be managed outside an HSM.
  software_management_exception: >
    DDKs only: all other P2PE keys (KEKs, BDKs, IPEKs, ZPKs) must remain in an HSM/SCD.
  usage_controls:
    cryptoperiod_option: >
      Define both a maximum transaction count AND a maximum time duration.  The DDK is
      retired when either limit is reached first (e.g., "1024 transactions or 24 hours").
    per_transaction_option: "Derive a unique DDK for every transaction (no reuse)."
  memory_erasure: >
    After use, DDKs must be erased from host volatile memory using an irrecoverable mechanism.
    The erasure mechanism must be validated by forensic testing (not just overwrite-with-zeros
    that a compiler might optimize away).
  derivation_rules:
    one_way: "If derived from a master key, derivation must be one-way (non-reversible)"
    not_a_variant: "DDK must not be a simple variant (XOR mask) of the master key"
    dedicated_master: "The master key used for DDK derivation must be dedicated to that purpose"
  transport_key_rules:
    strength: "Transport key must be at least as strong as the DDK it carries"
    uniqueness: "Transport key must be unique per Host System"
    single_purpose: "Transport key used ONLY for DDK delivery from HSM to Host System"
    cryptoperiod: "Transport key must have a defined cryptoperiod"
  merchant_managed_restriction: >
    Merchant-managed P2PE solutions are prohibited from using hybrid decryption entirely.
    They must use hardware decryption (all operations in HSM/SCD).
  apc_application: >
    APC can generate and manage DDKs as AES keys with TR-31 export under a Host System
    transport KEK.  The Host System receives the DDK encrypted in a TR-31 key block,
    decrypts it using its HSM-resident transport KEK, uses the DDK in volatile memory,
    then erases it.  Cryptoperiod enforcement must be implemented in the Host System's
    key management logic (APC does not enforce transaction counts).
constraints:
  - DDK is the ONLY P2PE key allowed to leave HSM custody (under transport key protection)
  - Usage limit must be transaction-count AND/OR time-based, or DDK must be per-transaction unique
  - Erasure from volatile memory must be forensically irrecoverable
  - Derivation must be one-way; DDK must not be a variant of the master key
  - Transport key: unique per Host System, single purpose, defined cryptoperiod
  - Hybrid mode prohibited for merchant-managed solutions (Appendix A)
references:
  - "PCI P2PE Standard v3.2 §Req 5H (pages 240-242)"
  - "PCI P2PE Standard v3.2 §Appendix A (page 248)"
relationships:
  - type: related_to
    target_id: concept.pci-p2pe-architecture
  - type: related_to
    target_id: concept.pci-pin-key-uniqueness-per-link
  - type: related_to
    target_id: concept.pci-p2pe-account-data-algorithms
status: active
```

---

### PCI P2PE: Cross-Level Key Variant Prohibition (Req 23)

```yaml
id: concept.pci-p2pe-key-variant-prohibition
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 23 — Reversible Cross-Level Transforms Prohibited; No DEKs Derived from KEKs
summary: >
  PCI P2PE Req 23 prohibits reversible transformations of keys across hierarchy levels.  A
  DEK (data encryption key, e.g., a DDK used for account-data encryption) must not be derived
  from a KEK (key encryption key) via a reversible or simple variant transform.  This prevents
  an attacker who recovers a DEK from reverse-engineering the KEK and thereby compromising the
  entire key hierarchy.  Only one-way derivation functions (e.g., a dedicated KDF) may be used
  to produce lower-level keys from higher-level keys.  This rule is the P2PE normative mirror
  of the same prohibition in PCI PIN.
domain:
  - compliance
  - key_management
  - cryptography
attributes:
  prohibited_transforms:
    - "XOR masking a KEK to produce a DEK (variant)"
    - "Truncating, reversing, or reordering bytes of a KEK to produce a DEK"
    - "Any bijective (reversible) function applied to a KEK to produce a DEK"
  permitted_approach: >
    Use a dedicated, one-way KDF (e.g., SP800-108 CMAC-based KDF) with distinct
    derivation parameters (labels, context) to produce DEKs from a dedicated master key.
    The master key used for DEK derivation must NOT also serve as a KEK.
  hierarchy_implication: >
    Each level of the key hierarchy must be cryptographically isolated from adjacent levels.
    Knowing a DEK must not provide any computational advantage in recovering a KEK or BDK.
  ddk_specific: >
    DDK derivation from a P2PE master key must follow the one-way rule.  If a DDK is
    derived from a master encryption key, that master key must be dedicated to DDK derivation
    and must not also be used as a KEK for transporting other keys.
constraints:
  - DEKs must not be derivable from KEKs via reversible transforms
  - No variant keys: simple XOR masks on KEKs to produce DEKs are prohibited
  - Master keys used for DEK derivation must be dedicated (single-purpose)
  - One-way KDF required for any cross-level key derivation
references:
  - "PCI P2PE Standard v3.2 §Req 23 (pages 190-193)"
relationships:
  - type: related_to
    target_id: concept.pci-p2pe-hybrid-ddk-controls
  - type: related_to
    target_id: concept.pci-pin-key-strength-hierarchy
status: active
```

---

### PCI P2PE: KEK-Must-Be-Stronger-Than-Protected-Key Rule (Req 10-1)

```yaml
id: concept.pci-p2pe-kek-transport-prohibition
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 10-1 — KEK Must Be At Least As Strong as the Key It Protects; TDEA Cannot Protect AES
summary: >
  PCI P2PE Req 10-1 requires that a key encryption key (KEK) used to transport or protect
  another key must be at least as strong (in bits of security) as the key it protects.
  The most operationally significant consequence is that TDEA (112-bit security equivalent)
  cannot protect (wrap or transport) an AES-128, AES-192, or AES-256 key (128/192/256-bit
  security).  Using a TDEA KEK to transport an AES key is treated as equivalent to sending
  the AES key in cleartext from a PCI perspective.  The normative Annex C footnote 6
  carves out a single exception: a 2048-bit RSA key (112-bit equivalent) may transport
  AES-128 for remote initial key distribution only.
domain:
  - compliance
  - key_management
  - cryptography
attributes:
  rule: >
    KEK security strength ≥ protected key security strength.
    TDEA (112-bit equivalent) cannot protect AES-128 (128-bit) or higher.
  prohibited_combinations:
    - "TDEA KEK wrapping AES-128 key (TDEA=112 bits < AES-128=128 bits)"
    - "TDEA KEK wrapping AES-192 key"
    - "TDEA KEK wrapping AES-256 key"
    - "RSA-2048 KEK wrapping AES-192 or AES-256 (permitted only for AES-128 per footnote 6)"
  permitted_combinations:
    - "AES-128 KEK wrapping AES-128 key (equal strength — permitted)"
    - "AES-256 KEK wrapping AES-128 or AES-256 key (stronger KEK — permitted)"
    - "RSA-2048 KEK wrapping AES-128 for remote key distribution (footnote 6 exception)"
    - "RSA-3072 KEK wrapping AES-128 (RSA-3072 = 128-bit equivalent — permitted)"
  footnote_6_exception: >
    RSA-2048 (112-bit equivalent) wrapping AES-128 is explicitly permitted for remote key
    distribution of initial keys (Annex C footnote 6). This is the ONLY exception to the
    KEK ≥ protected-key rule. It does NOT extend to AES-192 or AES-256.
  apc_implication: >
    When importing AES keys into APC via KEY_CRYPTOGRAM (asymmetric wrapping), the wrapping
    RSA key must be RSA-3072 or larger to protect AES-128 without relying on the footnote-6
    exception; or RSA-2048 may be used only for initial remote key load under footnote 6.
    APC's GetParametersForImport returns RSA-3072 or RSA-4096 wrapping keys by default,
    which satisfies this requirement.
constraints:
  - TDEA KEK prohibited from wrapping any AES key (TDEA < AES-128 in security strength)
  - RSA-2048 may only wrap AES-128 for remote key distribution (footnote 6); not AES-192/256
  - APC default import path (RSA-3072/4096 wrapping key) satisfies this requirement natively
references:
  - "PCI P2PE Standard v3.2 §Req 10-1 (pages 139-140)"
  - "PCI P2PE Standard v3.2 Normative Annex C Footnote 6 (page 245)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-tdes-aes-wrap-cleartext
  - type: related_to
    target_id: concept.pci-p2pe-account-data-algorithms
  - type: related_to
    target_id: concept.pci-pin-key-strength-hierarchy
status: active
```

---

### PCI P2PE: Key Destruction Witnessing and Documentation (Req 24-2)

```yaml
id: concept.pci-p2pe-key-destruction-witnessing
entity_type: compliance_rule
canonical_name: PCI P2PE Requirement 24-2 — Key Component Destruction Methods, Witness Requirements, and Affidavit Retention
summary: >
  PCI P2PE Req 24-2 defines acceptable physical destruction methods for paper key components
  and requires independent witnessing with a retained affidavit.  Acceptable destruction:
  cross-cut shredding, pulping, or burning.  Strip-shredding is explicitly NOT sufficient.
  Destruction must be witnessed by an individual who is NOT a custodian of the key being
  destroyed (Req 24-2.2).  A destruction affidavit must be retained for at least 2 years.
  Audit logs covering key lifecycle events must also be retained for at least 2 years (Req 25-6.1).
domain:
  - compliance
  - key_management
attributes:
  acceptable_destruction_methods:
    - "Cross-cut shredding (confetti/micro-cut shredder)"
    - "Pulping (paper reduced to pulp slurry)"
    - "Burning"
  prohibited_methods:
    - "Strip shredding (long strips can be reassembled)"
  witness_requirement: >
    The witness must be an individual who is NOT a custodian of the key being destroyed.
    Custodians (those with knowledge of or access to the key) cannot self-witness their
    own key destruction.
  affidavit_retention: "Destruction affidavit must be retained for at least 2 years"
  audit_log_retention: "Key lifecycle audit logs must be retained for at least 2 years (Req 25-6.1)"
  electronic_keys: >
    For electronic key material, secure erasure must be performed using cryptographic
    erase or physical destruction of the storage medium. The same witnessing and
    documentation principles apply.
  apc_application: >
    APC key deletion (delete_key or delete_key scheduling) generates audit trail entries
    in CloudTrail. For compliance, organizations should retain CloudTrail logs covering
    key creation through deletion for at least 2 years.  Physical key component
    ceremonies (if used for BYOK import) require non-custodian witnesses and affidavits.
constraints:
  - Strip shredding is explicitly prohibited for paper key components
  - Witness must not be a custodian of the key being destroyed
  - Destruction affidavit retained ≥2 years
  - Audit logs retained ≥2 years
references:
  - "PCI P2PE Standard v3.2 §Req 24-2 and §Req 24-2.2 (pages 195-198)"
  - "PCI P2PE Standard v3.2 §Req 25-6.1 (pages 200-201)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-compromise-response
status: active
```

---

## PCI MPoC Standard v1.1 — Acquirer-Relevant Rules

```yaml
id: concept.pci-mpoc-architecture
title: "PCI MPoC v1.1 — Architecture Overview and APC Applicability"
summary: >
  PCI Mobile Payments on COTS (MPoC) v1.1 (November 2024) governs software-based payment
  acceptance on commercial off-the-shelf (COTS) consumer devices (smartphones, tablets).
  The standard is organized into 5 domains:
    Domain 1 — Software-Based PIN Entry (if PIN is entered on the COTS device screen)
    Domain 2 — Account-Data Capture (card-present transactions without PIN on-device)
    Domain 3 — Attestation and Monitoring (A&M): continuous back-end monitoring of COTS device integrity
    Domain 4 — Back-End Operations: HSM requirements, key management, PIN processing compliance
    Domain 5 — Interfaces: communication security between COTS app and back-end
  Security model: The COTS device is treated as a hostile, uncontrolled execution environment
  (REE — Rich Execution Environment). Security relies on software protection mechanisms
  (white-box cryptography, obfuscation), attestation by a trusted back-end, and per-transaction
  key uniqueness with forward secrecy rather than hardware tamper-resistance.
  APC applicability: APC is the back-end HSM for MPoC Domain 4 operations. It satisfies
  Req 4A-2.2 (FIPS 140-2 Level 3 + PCI PTS HSM V3) and performs cryptographic operations
  inside the HSM (not merely key storage), making it suitable where cloud key-store-only
  HSMs are explicitly prohibited. PIN processing environments must hold valid PCI PIN AOC.
domain:
  - compliance
  - hsm
attributes:
  standard_version: "v1.1, November 2024"
  publisher: "PCI Security Standards Council"
  scope: "Software-based payment acceptance on COTS consumer devices (smartphones, tablets)"
  domains:
    - "Domain 1: Software-Based PIN Entry"
    - "Domain 2: Account-Data Capture"
    - "Domain 3: Attestation and Monitoring (A&M)"
    - "Domain 4: Back-End Operations"
    - "Domain 5: Interfaces"
  security_model: >
    COTS device is an untrusted REE. Security is achieved via software protection
    (white-box crypto), back-end attestation, and per-transaction key uniqueness with
    forward secrecy — not hardware tamper-resistance.
  apc_role: "Back-end HSM for Domain 4 operations (Req 4A-2.2 satisfied)"
  related_standards:
    - "PCI PIN (required for PIN-on-COTS environments, Req 4A-4.2)"
    - "PCI DSS (required for all back-end environments, Req 4A-4.1)"
    - "PCI PTS POI (referenced for hardware PIN entry comparison)"
constraints:
  - COTS device itself is not a PTS-approved POI device
  - Software protection and attestation are mandatory (not optional add-ons)
  - PIN environments must carry valid PCI PIN AOC
references:
  - "PCI MPoC Standard v1.1, Section 1 Overview (pages 15-35)"
  - "PCI MPoC Standard v1.1, Section 4A-4 (pages 180-181)"
relationships:
  - type: related_to
    target_id: concept.pci-mpoc-backend-hsm-requirement
  - type: related_to
    target_id: concept.apc-key-management-overview
status: active
```

---

```yaml
id: concept.pci-mpoc-backend-hsm-requirement
title: "PCI MPoC v1.1 Req 4A-2.2 — Back-End HSM Requirements and Cloud HSM Suitability"
summary: >
  MPoC Req 4A-2.2 mandates that back-end non-PIN account-data encryption/decryption keys
  reside in an HSM meeting one of three tiers:
    Tier 1 (Primary): FIPS 140-2 or FIPS 140-3 Level 3, OR PCI PTS HSM approved
    Tier 2 (Controlled Environment): FIPS 140-2 or FIPS 140-3 Level 2, in an ISO 13491
      Controlled Environment with documented physical and logical controls
    Tier 3 (Session/Forward-Secret): Keys are unique per transaction AND implement
      forward secrecy (so exposure of one key does not expose prior transactions)
  Critical cloud HSM suitability rule: The standard explicitly states that "Some Cloud HSM
  systems use the HSM only for storage of keys and allow for export of keys for cryptographic
  operations. These types of Cloud HSM systems are unsuitable for use with MPoC Solution."
  APC is NOT a key-store-only cloud HSM. APC performs cryptographic operations inside the
  HSM (TranslatePinData, EncryptData, GenerateMAC, etc.) — key material never leaves the HSM
  boundary in cleartext. APC therefore satisfies Tier 1 of Req 4A-2.2.
  Req 4A-2.4 additionally requires that cloud HSM keys be managed by the MPoC entity and
  NOT be accessible to the Cloud HSM provider. APC satisfies this: AWS cannot access customer
  key material; keys are created/controlled exclusively by the account owner.
domain:
  - compliance
  - hsm
  - key_management
attributes:
  requirement: "Req 4A-2.2"
  tiers:
    tier_1_primary:
      standard: "FIPS 140-2 or FIPS 140-3 Level 3, OR PCI PTS HSM approved"
      apc_status: "SATISFIED — APC is FIPS 140-2 Level 3 + PCI PTS HSM V3 certified"
    tier_2_controlled_env:
      standard: "FIPS 140-2 or FIPS 140-3 Level 2 in ISO 13491 Controlled Environment"
      apc_status: "Not applicable (APC qualifies at Tier 1)"
    tier_3_session_keys:
      standard: "Per-transaction unique keys with forward secrecy"
      apc_status: "Possible via DUKPT-derived session keys; APC provides BDK storage + DUKPT derivation"
  cloud_hsm_prohibition: >
    Cloud HSMs that only store keys and export them for cryptographic operations are
    EXPLICITLY UNSUITABLE. Operations must be performed inside the HSM boundary.
  apc_cloud_suitability: >
    APC performs all cryptographic operations inside the HSM. API calls (EncryptData,
    TranslatePinData, GenerateMAC, etc.) execute within the HSM; plaintext key material
    never leaves. APC satisfies the Req 4A-2.2 cloud HSM suitability test.
  key_ownership_req: >
    Req 4A-2.4: Cloud HSM keys must be managed by the MPoC entity and NOT accessible to
    the Cloud HSM provider. APC satisfies: AWS cannot access customer key material.
constraints:
  - Cloud HSMs that export keys for external crypto operations are prohibited
  - Back-end HSM must perform operations, not just store keys
  - Keys must be owned/controlled by the MPoC entity, not the HSM provider
references:
  - "PCI MPoC Standard v1.1, Req 4A-2.2 (pages 168-170)"
  - "PCI MPoC Standard v1.1, Req 4A-2.4 (page 170)"
relationships:
  - type: related_to
    target_id: concept.pci-mpoc-architecture
  - type: related_to
    target_id: concept.apc-key-management-overview
status: active
```

---

```yaml
id: concept.pci-mpoc-key-session-definition
title: "PCI MPoC v1.1 Req 1A-4.6 — Session Key Definition and HSM Residency Rule"
summary: >
  MPoC Req 1A-4.6 defines what constitutes a 'session' for key lifetime purposes and
  establishes where non-session keys must reside:
    - For PAN/account-data keys: session = a SINGLE transaction
    - For A&M (Attestation and Monitoring) keys: session ≤ 24 hours
  Non-session PIN and account-data keys must NEVER leave the back-end HSM in cleartext.
  This rule drives the architecture: either use per-transaction keys (DUKPT) or keep
  long-lived keys exclusively in APC and perform all operations via APC API calls.
domain:
  - compliance
  - key_management
  - pin_processing
attributes:
  requirement: "Req 1A-4.6"
  session_definitions:
    pan_account_data_keys: "Single transaction = one session"
    attestation_monitoring_keys: "≤24 hours = one session"
  non_session_key_rule: >
    Non-session PIN and account-data keys must never leave the back-end HSM in cleartext.
    This means long-lived BDKs, ZPKs, and similar keys must only be used via APC API
    calls — never exported in cleartext for external crypto.
  apc_implementation: >
    APC enforces this natively: keys with appropriate KeyUsage/KeyModesOfUse cannot be
    exported in cleartext. All cryptographic operations happen inside APC.
  forward_secrecy_context: >
    If account-data keys ARE exposed in the REE (COTS device), they must be
    per-transaction unique AND implement forward secrecy (see Req 1A-4.11/4.12 and
    concept.pci-mpoc-dukpt-forward-secrecy).
constraints:
  - Non-session account-data keys must never leave HSM in cleartext
  - A&M session keys expire after 24 hours maximum
  - PAN-encryption session keys expire after each transaction
references:
  - "PCI MPoC Standard v1.1, Req 1A-4.6 (page 65)"
relationships:
  - type: related_to
    target_id: concept.pci-mpoc-dukpt-forward-secrecy
  - type: related_to
    target_id: concept.pci-mpoc-backend-hsm-requirement
status: active
```

---

```yaml
id: concept.pci-mpoc-single-purpose-key-rule
title: "PCI MPoC v1.1 Req 1A-3.4 — Single-Purpose Key Rule"
summary: >
  MPoC Req 1A-3.4 mandates that each cryptographic key serve exactly one purpose.
  A key used for encrypting account data MUST NOT also be used for protecting
  tamper-detection or integrity data. A signing key must not also be an encryption key.
  Exception: TLS session keys are explicitly exempt from the single-purpose rule
  (TLS keys inherently serve authentication, key agreement, and data protection).
  This rule is consistent with PCI PIN Req 7-1 and PCI P2PE Req 23.
domain:
  - compliance
  - key_management
attributes:
  requirement: "Req 1A-3.4"
  rule: >
    One key = one purpose. Roles may not be combined: encryption keys are for
    encryption only; authentication keys are for authentication only; integrity
    keys are for integrity only.
  examples_of_violations:
    - "Using a PAN-encryption key to also MAC a tamper-detection log"
    - "Using a signing key to also encrypt data"
    - "Using a back-end encryption key as a KEK"
  tls_exception: "TLS session keys are exempt — they inherently combine key agreement, authentication, and encryption"
  cross_standard_consistency: "Consistent with PCI PIN Req 7-1 and PCI P2PE Req 23"
  apc_implementation: >
    APC enforces this via KeyUsage attributes (TR31_P0_PIN_ENCRYPTION,
    TR31_D0_SYMMETRIC_DATA_ENCRYPTION, TR31_M3_ISO_9797_3_MAC_GENERATION, etc.)
    and KeyModesOfUse (Encrypt, Decrypt, Generate, Verify). Setting a key's
    KeyUsage at creation time is the APC mechanism for single-purpose enforcement.
constraints:
  - Each key must have exactly one purpose/role
  - Account-data encryption keys cannot also serve as integrity/MAC keys
  - TLS keys are exempt
references:
  - "PCI MPoC Standard v1.1, Req 1A-3.4 (page 58)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-key-usage-restriction
  - type: related_to
    target_id: concept.pci-p2pe-key-variant-prohibition
status: active
```

---

```yaml
id: concept.pci-mpoc-dukpt-forward-secrecy
title: "PCI MPoC v1.1 Req 1A-4.11/4.12 — REE Account-Data Keys: Per-Transaction Uniqueness and Forward Secrecy"
summary: >
  When account-data encryption keys are exposed in the REE (COTS device, untrusted
  environment), MPoC Req 1A-4.11 and 1A-4.12 impose two mandatory properties:
    1. Per-transaction uniqueness: each transaction uses a distinct key
    2. Forward secrecy: compromise of any key must NOT allow derivation of prior
       transaction keys (one-way key disclosure)
  DUKPT (Derived Unique Key Per Transaction) is explicitly cited in the standard as a
  mechanism that can satisfy these requirements. In DUKPT, the BDK never enters the COTS
  device — only the Initial Key (IK/IPEK) is loaded, and per-transaction keys are derived
  forward-only. Compromise of a transaction key does not expose the BDK or prior keys.
  APC provides native DUKPT support: BDKs are stored in APC, and DUKPT key derivation
  and PIN/data translation are performed server-side via the APC data plane.
domain:
  - compliance
  - key_management
  - pin_processing
  - cryptography
attributes:
  requirements:
    - "Req 1A-4.11: REE-exposed account-data keys must be per-transaction unique"
    - "Req 1A-4.12: One-way key disclosure (forward secrecy); DUKPT cited as satisfying mechanism"
  ree_definition: "Rich Execution Environment — the untrusted COTS OS/app layer"
  dukpt_properties:
    bdk_protection: "BDK never loaded to COTS device; only IPEK/IK is loaded"
    forward_secrecy: "Transaction key derivation is one-way; compromise does not reveal BDK or prior keys"
    per_transaction: "Each transaction derives a unique key via KSN counter increment"
  apc_support: >
    APC stores BDKs and performs DUKPT-based translation (TranslatePinData with DUKPT
    parameters). BDK never leaves APC. IPEK derivation and per-transaction key derivation
    happen inside APC for server-side operations, or IPEK is securely loaded to device
    for on-device derivation.
  key_types_covered: "Account-data encryption keys exposed in REE; applies to both AES DUKPT and TDES DUKPT"
constraints:
  - REE-exposed account-data keys must be per-transaction unique
  - Compromise of one transaction key must not expose prior transaction keys
  - DUKPT satisfies both requirements when implemented correctly
references:
  - "PCI MPoC Standard v1.1, Req 1A-4.11 and Req 1A-4.12 (page 68)"
relationships:
  - type: related_to
    target_id: concept.pci-mpoc-key-session-definition
  - type: related_to
    target_id: concept.dukpt-aes
  - type: related_to
    target_id: concept.pci-p2pe-hybrid-ddk-controls
status: active
```

---

```yaml
id: concept.pci-mpoc-algorithm-requirements
title: "PCI MPoC v1.1 — Minimum Algorithm Requirements and Key Equivalence (Appendix C)"
summary: >
  MPoC Appendix C Tables 7 and 8 define minimum acceptable cryptographic algorithm
  parameters. These are NORMATIVE — algorithms below minimum are non-compliant.
  The tables are IDENTICAL to PCI PIN Annex C and PCI P2PE Annex C: all three
  PCI standards agree on minimum key sizes and equivalence levels.
  Minimums (Table 7):
    Symmetric:  AES ≥ 128 bits; TDEA ≥ 168 bits (3-key); 2-key TDEA not mentioned (prohibited for new use)
    Asymmetric: RSA ≥ 2048 bits; ECC ≥ 224 bits; FFC (DH/DSA) ≥ 2048-bit prime / 224-bit subgroup
    Hash:       SHA-2 > 255 bits (SHA-256, SHA-384, SHA-512); SHA-3 > 255 bits; SHA-1 NOT permitted
    KCV:        AES: CMAC of all-zero plaintext, leftmost 10 hex digits; TDEA: ECB encrypt all-zero, leftmost 6 hex digits
  Special rule — RSA-2048 wrapping larger AES (Req 1A-3.2):
    RSA-2048 MAY be used to protect AES keys of ANY size (128-256 bit) when the COTS
    platform prevents use of larger RSA keys. This is broader than the PCI P2PE footnote 6
    exception (which was AES-128 only). KEK minimum = 128 bits of security.
  Equivalence table (Table 8): 112 bits = RSA-2048/ECC-224/FFC-2048-224;
    128 bits = RSA-3072/ECC-256/FFC-3072-256/AES-128; 192 bits = RSA-7680/ECC-384/AES-192;
    256 bits = RSA-15360/ECC-512/AES-256
domain:
  - compliance
  - cryptography
  - key_management
attributes:
  standard_appendix: "Appendix C (pages 237-239)"
  cross_standard_consistency: "Tables 7 and 8 are identical to PCI PIN Annex C and PCI P2PE Annex C"
  minimum_key_sizes:
    aes: "≥128 bits"
    tdea: "≥168 bits (3-key TDEA only)"
    rsa: "≥2048 bits"
    ecc: "≥224 bits"
    ffc: "≥2048-bit prime / 224-bit subgroup"
  hash_requirements:
    required: ["SHA-256", "SHA-384", "SHA-512", "SHA-3 (>255 bit variants)"]
    prohibited: ["SHA-1 (for any security purpose)", "MD5"]
  kcv_methods:
    aes: "CMAC over all-zero block, take leftmost 10 hex digits (5 bytes)"
    tdea: "ECB encrypt all-zero block, take leftmost 6 hex digits (3 bytes)"
  rsa2048_exception: >
    Req 1A-3.2: RSA-2048 may wrap AES keys of any size (128-256 bit) when the COTS
    platform prevents use of RSA ≥ 3072. This is broader than P2PE footnote 6 (AES-128
    only). The KEK must provide ≥128 bits of security.
  equivalence_table:
    112_bits: ["RSA-2048", "ECC-224", "FFC-2048/224"]
    128_bits: ["RSA-3072", "ECC-256", "FFC-3072/256", "AES-128"]
    192_bits: ["RSA-7680", "ECC-384", "AES-192"]
    256_bits: ["RSA-15360", "ECC-512", "AES-256"]
constraints:
  - SHA-1 is NOT permitted for any security purpose
  - AES KCV must use CMAC method, not legacy ECB-zero method
  - RSA-2048 wrapping any AES size requires COTS-platform justification
references:
  - "PCI MPoC Standard v1.1, Appendix C Tables 7-8 (pages 237-239)"
  - "PCI MPoC Standard v1.1, Req 1A-3.2 (page 57)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-algorithm-requirements
  - type: related_to
    target_id: concept.pci-p2pe-account-data-algorithms
status: active
```

---

## PCI CPoC Standard v1.0 — Acquirer-Relevant Rules

```yaml
id: concept.pci-cpoc-architecture
title: "PCI CPoC v1.0 — Architecture Overview and Scope"
summary: >
  PCI Contactless Payments on COTS (CPoC) v1.0 (December 2019) governs contactless-only
  payment acceptance on COTS devices (smartphones, tablets) using the device's native NFC
  interface. It differs critically from MPoC:
    - CPoC = contactless (NFC) card reading ONLY; software-based PIN entry is EXPLICITLY
      PROHIBITED by CPoC ("Software-based PIN entry is not permitted in CPoC solution")
    - CPoC supports only online chip-based transactions; offline EMV and deferred
      authorization are prohibited
    - The security model relies on software protection mechanisms, attestation, and
      monitoring — identical in structure to MPoC but without the PIN security domain
  Structure: 5 Modules
    Module 1 — Core Requirements: crypto, key management, secure channels, correlatable data
    Module 2 — CPoC Application: tamper/reverse-engineering protection, software-protected
      cryptography, account data encryption
    Module 3 — Back-end Systems — Monitoring/Attestation: continuous back-end monitoring
    Module 4 — Back-end Systems — Processing: account data decryption + PCI DSS compliance
    Module 5 — Contactless Kernel: EMV contactless kernel requirements
  APC applicability: APC handles account data decryption in the back-end (Module 4).
  Module 4 requires PCI DSS compliance but does NOT impose an explicit FIPS Level 3
  HSM requirement (unlike MPoC Req 4A-2.2). Back-end key management still benefits
  from APC for strong cryptographic isolation and audit trail.
domain:
  - compliance
  - hsm
attributes:
  standard_version: "v1.0, December 2019"
  publisher: "PCI Security Standards Council"
  scope: "Contactless-only (NFC) payment acceptance on COTS devices"
  software_pin_entry: "EXPLICITLY PROHIBITED in CPoC — use MPoC for software PIN"
  offline_transactions: "PROHIBITED — only online chip-based transactions supported"
  modules:
    - "Module 1: Core Requirements (crypto, key mgmt, secure channels)"
    - "Module 2: CPoC Application (software protection, account data encryption)"
    - "Module 3: Back-end Monitoring/Attestation"
    - "Module 4: Back-end Processing (PCI DSS, account data decryption)"
    - "Module 5: Contactless Kernel (EMV contactless)"
  vs_mpoc: >
    CPoC = contactless NFC read only; MPoC = PIN entry + contactless + other mobile payment
    mechanisms. Use CPoC standard for tap-to-pay acceptance without PIN on COTS device.
    Use MPoC when PIN entry is involved.
  related_standards:
    - "PCI DSS (required for back-end processing environment, Module 4)"
    - "EMVCo contactless specifications (Module 5)"
constraints:
  - Software-based PIN entry is prohibited in CPoC solutions
  - Only online, chip-based contactless transactions are permitted
  - Back-end payment processing environment must comply with PCI DSS
references:
  - "PCI CPoC Standard v1.0, Introduction/Purpose (pages 5-6)"
  - "PCI CPoC Standard v1.0, Overview (pages 17-20)"
relationships:
  - type: related_to
    target_id: concept.pci-mpoc-architecture
  - type: related_to
    target_id: concept.pci-cpoc-account-data-encryption
status: active
```

---

```yaml
id: concept.pci-cpoc-account-data-encryption
title: "PCI CPoC v1.0 Req 2.9 — Account Data Encryption: Application Layer Required, Per-Transaction Keys"
summary: >
  CPoC Section 2.9 defines mandatory account data encryption requirements:
  
  Application-layer encryption is REQUIRED. TLS (secure channel alone) is NOT sufficient.
  The standard explicitly states: "A secure channel cannot be used as the sole security
  and encryption mechanism. Protocol-level encryption, such as TLS, does not meet this
  requirement, which requires for application-level encryption." The account data must be
  encrypted within the CPoC application before transmission — separate from TLS.
  
  Per-transaction unique keys (Req 2.9.2): The encryption key for each NFC contactless
  reading must be unique per transaction. The key must be permanently deleted after the
  transaction terminates (regardless of success or failure). The unique key cannot be
  calculated from the previous key (one-way key derivation = forward secrecy). This is
  the same forward-secrecy requirement as MPoC Req 1A-4.11/4.12.
  
  Key derivation techniques and key negotiation techniques are cited as acceptable
  methods for achieving per-transaction unique key generation.
  
  After encryption, any remaining cleartext account data on the COTS device must be
  permanently deleted. If a split contactless kernel implementation passes data
  back and forth, all remnants must be deleted at transaction end.
domain:
  - compliance
  - key_management
  - cryptography
attributes:
  requirements:
    - "Req 2.9.1: Application-layer encryption required; TLS alone is insufficient"
    - "Req 2.9.2: Per-transaction unique key; key deleted after transaction; forward secrecy (one-way derivation)"
    - "Req 2.9.3: Encrypted data protected from replay attacks; per-transaction unique keys prevent replay"
    - "Req 2.9.4: Integrity AND confidentiality of account data; must meet Section 1.3 crypto requirements"
  tls_insufficiency: >
    TLS is a secure channel but does NOT satisfy account data encryption requirements.
    Account data must be encrypted at the application layer, specifically to the elements
    containing account data. TLS only protects data in transit, not at rest in memory.
  per_transaction_key_rule: >
    One key per contactless reading (transaction). Key permanently deleted after transaction
    terminates. No subsequent key can be derived from a prior key (one-way derivation /
    forward secrecy). Key derivation techniques (e.g., DUKPT) and key negotiation
    techniques satisfy this requirement.
  cleartext_deletion: >
    After encryption, any cleartext account data on the COTS device must be permanently
    deleted. In split contactless kernel implementations, all remnants of account data
    must be deleted at transaction end.
  apc_implementation: >
    For back-end key material (BDK storage): APC is the natural home for BDKs used to
    derive per-transaction keys via DUKPT. The CPoC application generates or derives
    per-transaction keys from an IPEK loaded at provisioning time, with the BDK staying
    in APC. APC decrypts the account data server-side.
constraints:
  - TLS/secure channel alone does NOT satisfy account data encryption
  - Encryption must be at application layer (not just transport layer)
  - Encryption key must be per-transaction unique
  - Key must be permanently deleted after each transaction
  - One-way key derivation required (compromise of tx key ≠ compromise of prior tx keys)
references:
  - "PCI CPoC Standard v1.0, Section 2.9 Account Data Encryption (pages 86-87)"
  - "PCI CPoC Standard v1.0, Section 1.5.3 (page 44) — channel keys separate from data encryption keys"
relationships:
  - type: related_to
    target_id: concept.pci-cpoc-architecture
  - type: related_to
    target_id: concept.pci-mpoc-dukpt-forward-secrecy
  - type: related_to
    target_id: concept.dukpt-aes
status: active
```

---

```yaml
id: concept.pci-cpoc-backend-processing
title: "PCI CPoC v1.0 Module 4 — Back-End Processing: Decryption Only in Back-End, PCI DSS Required"
summary: >
  CPoC Module 4 (Section 4.1) governs the back-end payment processing environment:
  
  Req 4.1.1: ALL account data decryption must occur ONLY in the back-end payment
  processing environment. Decrypted account data must NOT be returned to the COTS device
  after decryption (exception: a split contactless kernel that requires data round-trip
  for processing — but only as part of the remote kernel operation, not for general use).
  
  Req 4.1.2: The back-end payment processing environment must comply with PCI DSS and
  must have a valid Attestation of Compliance (AOC) covering the payment processing scope.
  
  Notable difference from MPoC: CPoC Module 4 does NOT impose an explicit FIPS Level 3
  HSM requirement for account data decryption keys. It requires PCI DSS compliance for
  the back-end environment. MPoC Req 4A-2.2, in contrast, explicitly requires FIPS 140-2/3
  Level 3 or PCI PTS HSM for non-PIN back-end keys. For CPoC implementations, APC is
  still the recommended choice because it provides strong key isolation, CloudTrail audit
  trail, and satisfies PCI DSS encryption requirements by design.
domain:
  - compliance
  - key_management
  - hsm
attributes:
  requirements:
    - "Req 4.1.1: Decryption only in back-end; decrypted data never returned to COTS device"
    - "Req 4.1.2: PCI DSS compliance required; valid AOC required"
  vs_mpoc_hsm_requirement: >
    CPoC does NOT require FIPS Level 3 HSM explicitly. MPoC Req 4A-2.2 does. For CPoC,
    PCI DSS compliance for the back-end processing environment is the stated requirement.
    However, PCI DSS Req 3.6 requires strong cryptography for encryption key management,
    which in practice is best satisfied by an HSM like APC.
  apc_advantages: >
    Even without an explicit HSM mandate in CPoC, APC provides: (1) FIPS 140-2 Level 3
    certified key storage and operations, (2) immutable CloudTrail audit logs for PCI DSS
    compliance, (3) separation of key material from application code, (4) data plane API
    for account data decryption without key export.
  remote_kernel_exception: >
    If a contactless kernel is split (partially remote/cloud-hosted), the remote kernel
    environment must also comply with PCI DSS (Req 5.2.2).
constraints:
  - Decryption of account data must occur exclusively in back-end environments
  - Decrypted data must never be returned to the COTS device
  - Back-end processing environment requires PCI DSS AOC
references:
  - "PCI CPoC Standard v1.0, Module 4 Section 4.1 (page 117)"
  - "PCI CPoC Standard v1.0, Section 5.2.2 (page 121)"
relationships:
  - type: related_to
    target_id: concept.pci-cpoc-architecture
  - type: related_to
    target_id: concept.pci-mpoc-backend-hsm-requirement
status: active
```

---

```yaml
id: concept.pci-cpoc-algorithm-requirements
title: "PCI CPoC v1.0 — Algorithm Requirements: No TDEA, AES-Only Symmetric, Appendix C"
summary: >
  CPoC Appendix C (Table 7) lists ONLY four algorithm families as approved for the solution.
  Notably, TDEA/3DES is NOT listed — unlike PCI PIN Annex C and PCI P2PE Annex C which
  both include TDEA ≥ 168 bits. CPoC is the most modern of the three standards (2019) and
  treats AES as the only approved symmetric cipher.
  
  Approved algorithm minimums (Table 7):
    IFC (RSA):           ≥ 2048 bits
    ECC (ECDSA, ECDH):   ≥ 224 bits
    FFC (DSA, DH, MQV):  ≥ 2048-bit prime / 224-bit subgroup
    AES:                 ≥ 128 bits
    TDEA:                NOT LISTED (not approved in CPoC)
  
  Hash algorithms (Table 9): SHA-2 family >255 bits; SHA-3 family >255 bits (only).
  
  Equivalent key sizes (Table 8): Same as PCI PIN and P2PE:
    112 bits = RSA-2048 / ECC-224 / FFC-2048/224
    128 bits = RSA-3072 / ECC-256 / FFC-3072/256 / AES-128
    192 bits = RSA-7680 / ECC-384 / AES-192
    256 bits = RSA-15360 / ECC-512 / AES-256
  
  KCV (from Appendix C p.147): TDEA = ECB encrypt all-zero block, leftmost 24 bits
  (note: standard text has a typographical inconsistency — it says "24 bits" alongside
  "10 hexadecimal digits or 5 bytes"; per PCI PIN Annex C the correct value is 6 hex
  digits / 3 bytes for TDEA); AES = CMAC all-zero block, leftmost 10 hex digits (5 bytes).
  
  Single-purpose key rule (Req 1.3.8): Each key must have a single unique purpose;
  account data encryption keys must not be used for attestation message encryption
  or any other purpose. This mirrors MPoC Req 1A-3.4 and PCI PIN Req 7-1.
  
  KEK strength rule (Req 1.3.4): A KEK must be of equal or greater strength than any
  key it protects. A 128-bit AES KEK cannot protect a 256-bit AES key.
  
  Self-signed certificates (Req 1.3.6): Prohibited in CPoC solution components.
  Exception: self-signed certificates that are part of the base COTS platform are excluded.
domain:
  - compliance
  - cryptography
  - key_management
attributes:
  standard_appendix: "Appendix C (pages 146-148)"
  tdea_status: "NOT APPROVED — CPoC Appendix C Table 7 does not include TDEA as an approved algorithm"
  tdea_comparison: >
    PCI PIN Annex C and P2PE Annex C both list TDEA ≥ 168 bits as an approved minimum.
    CPoC (2019) omits TDEA entirely from Table 7, making AES-128 the only approved
    symmetric cipher for CPoC solutions.
  minimum_key_sizes:
    aes: "≥128 bits (ONLY approved symmetric cipher)"
    rsa: "≥2048 bits"
    ecc: "≥224 bits"
    ffc: "≥2048-bit prime / 224-bit subgroup"
    tdea: "NOT LISTED (not approved)"
  hash_requirements:
    required: ["SHA-256", "SHA-384", "SHA-512", "SHA-3 (>255 bit variants)"]
    note: "MD5 and SHA-1 permitted ONLY for non-security uses (e.g., file comparison where collision resistance not needed)"
  kcv_methods:
    tdea: "ECB encrypt all-zero block; leftmost 3 bytes (6 hex digits) — note: CPoC Appendix C has a typographical error stating '24 bits' where it should be '40 bits / 5 bytes / 10 hex digits'"
    aes: "CMAC over all-zero block; leftmost 10 hex digits (5 bytes)"
  equivalence_table:
    112_bits: ["RSA-2048", "ECC-224", "FFC-2048/224"]
    128_bits: ["RSA-3072", "ECC-256", "FFC-3072/256", "AES-128"]
    192_bits: ["RSA-7680", "ECC-384", "AES-192"]
    256_bits: ["RSA-15360", "ECC-512", "AES-256"]
  cross_standard_note: >
    Equivalence table is identical to PCI PIN Annex C and PCI P2PE Annex C and MPoC
    Appendix C. All four standards agree on equivalent key sizes. The only divergence
    is CPoC's omission of TDEA from approved algorithms.
  single_purpose_rule: "Req 1.3.8 — each key one purpose; account data encryption ≠ attestation MAC"
  kek_strength_rule: "Req 1.3.4 — KEK must be equal or greater strength than key it protects"
  self_signed_cert_prohibition: "Req 1.3.6 — self-signed certificates prohibited (COTS platform certs excepted)"
constraints:
  - TDEA/3DES is NOT an approved algorithm in CPoC (no Table 7 entry)
  - AES-128 is the minimum symmetric cipher; AES-256 preferred
  - SHA-256+ required for security-relevant hashing; SHA-1 only for non-security uses
  - KEK strength ≥ protected key strength (Req 1.3.4)
references:
  - "PCI CPoC Standard v1.0, Appendix C Tables 7-9 (pages 146-148)"
  - "PCI CPoC Standard v1.0, Section 1.3 Acceptable Cryptography (pages 32-36)"
relationships:
  - type: related_to
    target_id: concept.pci-pin-algorithm-requirements
  - type: related_to
    target_id: concept.pci-p2pe-account-data-algorithms
  - type: related_to
    target_id: concept.pci-mpoc-algorithm-requirements
status: active
```

---

## PCI 3DS Core Security Standard v1.0 — Acquirer-Relevant Rules

```yaml
id: concept.pci-3ds-architecture
title: PCI 3DS Core Security Standard — Architecture and Scope
tags: [compliance, 3ds, emv, key_management, hsm]
source: PCI 3DS Core Security Standard v1.0, October 2017
status: active
```

PCI 3DS v1.0 covers security requirements for EMV 3-D Secure (3DS) protocol
implementations. Three core entities form the 3DS ecosystem:

- **ACS** (Access Control Server): issuer-side; authenticates cardholders; MUST use an HSM
- **DS** (Directory Server): scheme-operated (e.g., Visa, Mastercard); routes between 3DSS and ACS; MUST use an HSM
- **3DSS** (3DS Server): acquirer/merchant-side; initiates auth requests; HSM NOT required but strongly recommended

The **3DE** (3DS Data Environment) is the secure boundary within which 3DS functions occur.
The 3DSS "links to the Acquirer and initiates authorization requests" — it is the primary
acquirer-facing component and the one most directly relevant to APC deployments.

**Two parts with different scopes:**
- Part 1 (P1-1 through P1-7): Baseline Security Requirements — generic security controls
  analogous to PCI DSS; entities with valid PCI DSS AOC may leverage it to satisfy Part 1
  for their 3DE (Appendix B). Part 1 covers policies, network, SDLC, access, physical,
  monitoring, incident response.
- Part 2 (P2-1 through P2-7): 3DS-specific requirements — ALWAYS apply regardless of
  PCI DSS compliance status. Cannot be satisfied by PCI DSS AOC alone.
  Part 2 covers: authentication, data protection, access control, application security,
  Protect 3DS data (P2-5), Cryptography and Key Management (P2-6), Physical security (P2-7).

**APC relevance**: APC is the natural back-end cryptographic service for 3DSS operators
(acquirer/processor side). ACS and DS are typically issuer/scheme infrastructure outside
acquirer scope. For acquirers building or operating 3DSS functionality, APC provides the
strongly recommended HSM tier for key management.

---

```yaml
id: concept.pci-3ds-hsm-requirement
title: PCI 3DS HSM Requirements — Who Must Use an HSM and What Level
tags: [compliance, 3ds, hsm, key_management, fips]
source: PCI 3DS Core Security Standard v1.0, Req P2-6.1.2, P2-6.2, P2-6.3
status: active
```

**Req P2-6.1.2 — HSM Requirement (ACS and DS only):**
- HSM is MANDATORY for ACS and DS for all key management activities specified in the
  PCI 3DS Data Matrix (key-encryption, decryption, key generation, storage).
- HSM must be EITHER:
  - FIPS 140-2 Level 3 (overall) certified (NIST CMVP listing with valid number), OR
  - PCI PTS HSM approved (valid PCI SSC listing number, approval class "HSM")
- "It is not required that 3DSS entities use an HSM to manage 3DS keys; however it is
  strongly recommended." — 3DSS is subject to all other key management requirements.

**APC satisfies both criteria for ACS/DS:**
- APC is FIPS 140-2 Level 3 certified AND PCI PTS HSM V3 approved.
- For ACS or DS operators migrating from physical HSMs, APC is a direct qualifying replacement.
- For 3DSS (acquirer-side), APC satisfies the "strongly recommended" HSM tier and all
  P2-6 key management requirements without the mandatory classification.

**HSM logical access (P2-6.2, ACS and DS only):**
- Personnel must access HSMs at console or via ISO 13491-evaluated non-console solution.
- Single DEA message authentication codes are explicitly NOT permitted (6.2.1 note).
- Only NIST SP 800-90A compliant RNGs allowed.
- Loading/exporting clear-text keys, key components, or key shares over a non-console
  connection is PROHIBITED (Req 6.2.4).
- All non-console HSM access must originate from within the 3DE network.

**Physical security (P2-6.3, P2-7 — ACS and DS only):**
- HSMs stored in dedicated areas; physical access under dual control.
- ACS and DS must be in data center environments with mantrap and CCTV.
- P2-7 physical requirements do NOT apply to 3DSS.
- APC eliminates all P2-6.2/6.3 and P2-7 burden for the HSM layer — AWS manages
  physical security, logical access, and the certified hardware boundary.

---

```yaml
id: concept.pci-3ds-key-management
title: PCI 3DS Key Management Requirements
tags: [compliance, 3ds, key_management, cryptography, single_purpose]
source: PCI 3DS Core Security Standard v1.0, Req P2-6.1.5 through P2-6.1.10
status: active
```

**Req P2-6.1.5 — Full key lifecycle management required for all 3DS entities:**
Full lifecycle must be addressed: generation, distribution/conveyance, storage, crypto period
establishment, rotation when crypto period reached, escrow/backup, compromise and recovery,
emergency destroy-and-replace procedures, accountability and audit.

Key management must conform to recognized national/international standards (Req 6.1.6):
- NIST SP 800-57 (all parts) — key management recommendations
- NIST SP 800-90A — deterministic random bit generation
- ISO 11568 — financial services key management
- ISO/IEC 11770 — key management techniques

**Req P2-6.1.7 — Single-purpose key rule (consistent across all PCI standards):**
"Cryptographic keys are used only for their intended purpose, and keys used for 3DS functions
are not used for non-3DS purposes." A KEK must never be used to encrypt 3DS sensitive data
directly. Public keys only for encryption or signature verification; private keys only for
decryption or signature creation. Keys for 3DS must not serve any business function outside 3DS.

Cross-standard consistency: same rule as PCI PIN Req 7-1, MPoC Req 1A-3.4, CPoC Req 1.3.8.
APC enforces this via key usage attributes (KeyUsage field on every key).

**Req P2-6.1.8 — Trusted CA required:**
All digital certificates used for 3DS operations between 3DSS, ACS, and DS must use a trusted CA.
Self-signed certificates are not addressed but implicit in the "trusted CA" framing.

**Req P2-6.1.9 — Key management audit log required:**
Audit logs for ALL key management activities and clear-text key component handling must record:
- Identity of the individual performing the function
- Date and time
- Function being performed
- Purpose of the affected key
- Success or failure of the activity

**TLS cipher suite requirements (Req P2-5.3):**
- Approved cipher suites defined in EMV 3DS Protocol and Core Functions Specification, Annex D.
- 3DS components (ACS, DS, 3DSS) must not offer or support cipher suites listed as
  "not supported" in that specification.
- TLS configurations must not support rollback to unapproved algorithms/key sizes.
- "The use of 3DES and SHA-1 should be phased out" — flagged in the 2017 standard for
  future deprecation. (Note: this is TLS cipher context, not symmetric key wrapping.)
- No fallback to insecure protocols permitted (Req 5.2.2).

**Application-layer encryption (Req P2-5.4.2):**
3DS sensitive data in storage must be protected with strong cryptography beyond TLS.
May encrypt individual data elements or the containing data packet/file. One-way hashes
with a strong salt are acceptable where retrieval is not required.

---
```

---

## EMV Tag Catalog

Source: EMV Integrated Circuit Card Specifications for Payment Systems, Book 3 — Application Specification,
v4.4, October 2022 (EMVCo), Annex A (Data Elements Dictionary). This supersedes the prior kabc.ca-sourced
catalog; corrections include: tag 91 length (8–16 not 8), exponent tags (1 or 3 not 3), 9F3B length (2–8),
9F41 length (2–4), added missing Book 3 tags (42, 4F, 73, 81, 83, 86–89, 9F0A, 9F0C, 9F19, 9F25), added
biometric tags (7F60, A1, 9F30, 9F31, BF4A–BF4E, DF50–DF54, new in v4.4). Scheme-proprietary tags
(Mastercard 9F51+, Visa, contactless kernel) are in a separate subsection below.

### EMVCo Book 3 v4.4 — Authoritative Tags

| Tag | Name | Source | Fmt | Length | Notes |
|-----|------|--------|-----|--------|-------|
| 42 | Issuer Identification Number (IIN) | ICC | n 6 | 3 | First 6 digits of PAN; identifies major industry and issuer |
| 4F | Application Dedicated File (ADF) Name | ICC | b | 5–16 | AID stored on card (ISO/IEC 7816-5) |
| 50 | Application Label | ICC | ans | 1–16 | Mnemonic for AID; special chars limited to space |
| 57 | Track 2 Equivalent Data | ICC | b | ≤19 | Track 2 data minus start/end sentinel and LRC |
| 5A | Application Primary Account Number (PAN) | ICC | cn | ≤10 | Up to 19 decimal digits; cn encoding |
| 5F20 | Cardholder Name | ICC | ans | 2–26 | Per ISO/IEC 7813 |
| 5F24 | Application Expiration Date | ICC | n 6 (YYMMDD) | 3 | |
| 5F25 | Application Effective Date | ICC | n 6 (YYMMDD) | 3 | |
| 5F28 | Issuer Country Code | ICC | n 3 | 2 | ISO 3166-1 numeric |
| 5F2A | Transaction Currency Code | Terminal | n 3 | 2 | ISO 4217 numeric; ARQC input |
| 5F2D | Language Preference | ICC | an 2 | 2–8 | ISO 639; 1–4 codes; recommend lowercase |
| 5F30 | Service Code | ICC | n 3 | 2 | Magnetic stripe service code |
| 5F34 | Application PAN Sequence Number | ICC | n 2 | 1 | Differentiates cards with same PAN |
| 5F36 | Transaction Currency Exponent | Terminal | n 1 | 1 | Decimal places in transaction amount |
| 5F50 | Issuer URL | ICC | ans | var. | Issuer library server URL |
| 5F53 | International Bank Account Number (IBAN) | ICC | var. | ≤34 | ISO 13616 |
| 5F54 | Bank Identifier Code (BIC) | ICC | var. | 8 or 11 | ISO 9362 |
| 5F55 | Issuer Country Code (alpha2) | ICC | a 2 | 2 | ISO 3166-1 alpha-2 |
| 5F56 | Issuer Country Code (alpha3) | ICC | a 3 | 3 | ISO 3166-1 alpha-3 |
| 5F57 | Account Type | Terminal | n 2 | 1 | Values per Annex G |
| 61 | Application Template | ICC | b | ≤252 | Directory entry template |
| 6F | File Control Information (FCI) Template | ICC | var. | ≤252 | Per ISO/IEC 7816-4 |
| 70 | READ RECORD Response Message Template | ICC | — | — | AEF data template |
| 71 | Issuer Script Template 1 | Issuer | b | var. | Script commands before second GENERATE AC |
| 72 | Issuer Script Template 2 | Issuer | b | var. | Script commands after second GENERATE AC |
| 73 | Directory Discretionary Template | ICC | var. | ≤252 | Issuer discretionary directory data |
| 77 | Response Message Template Format 2 | — | — | — | TLV-encoded GPO/GENERATE AC response |
| 80 | Response Message Template Format 1 | — | — | — | Non-TLV response |
| 81 | Amount, Authorised (Binary) | Terminal | b | 4 | Binary authorised amount (excluding adjustments) |
| 82 | Application Interchange Profile (AIP) | ICC | b | 2 | Bitmap of card capabilities (SDA/DDA/CDA, contactless, etc.) |
| 83 | Command Template | Terminal | b | var. | GENERATE AC command data field identifier |
| 84 | Dedicated File (DF) Name | ICC | b | 5–16 | ISO/IEC 7816-4 DF name |
| 86 | Issuer Script Command | Issuer | b | ≤261 | Command for transmission to ICC |
| 87 | Application Priority Indicator | ICC | b | 1 | Priority in application selection |
| 88 | Short File Identifier (SFI) | ICC | b | 1 | File pointer for READ RECORD |
| 89 | Authorisation Code | Issuer | per PS | 6 | Auth code generated by authorisation authority |
| 8A | Authorisation Response Code | Issuer/Terminal | an 2 | 2 | e.g. 00=approved, 05=declined |
| 8C | CDOL1 | ICC | b | ≤252 | DOL for first GENERATE AC |
| 8D | CDOL2 | ICC | b | ≤252 | DOL for second GENERATE AC |
| 8E | CVM List | ICC | b | 10–252 | Cardholder verification method rules |
| 8F | Certification Authority Public Key Index | ICC | b | 1 | CA PK index; used with RID |
| 90 | Issuer Public Key Certificate | ICC | b | var. | RSA or ECC issuer cert signed by CA |
| 91 | Issuer Authentication Data | Issuer | b | 8–16 | ARPC (Method 1: 8 bytes); ARPC+CSU+proprietary (Method 2: up to 16 bytes) |
| 92 | Issuer Public Key Remainder | ICC | b | var. | Overflow bytes of issuer key modulus |
| 93 | Signed Static Application Data (SSAD) | ICC | b | N_I | SDA signature |
| 94 | Application File Locator (AFL) | ICC | var. | ≤252 | SFI/record ranges to read |
| 95 | Terminal Verification Results (TVR) | Terminal | b | 5 | Offline check bitmap; ARQC input |
| 97 | Transaction Certificate Data Object List (TDOL) | ICC | b | ≤252 | DOL for TC hash computation |
| 98 | TC Hash Value | Terminal | b | 20 | SHA-1 hash of TC data |
| 99 | Transaction PIN Data | Terminal | b | var. | Online PIN block |
| 9A | Transaction Date | Terminal | n 6 (YYMMDD) | 3 | ARQC input |
| 9B | Transaction Status Information (TSI) | Terminal | b | 2 | Card processing status bitmap |
| 9C | Transaction Type | Terminal | n 2 | 1 | First 2 digits of ISO 8583:1987 Processing Code |
| 9D | Directory Definition File (DDF) Name | ICC | b | 5–16 | PSE DDF |
| 9F01 | Acquirer Identifier | Terminal | n 6–11 | 6 | Acquirer institution ID |
| 9F02 | Amount, Authorised (Numeric) | Terminal | n 12 | 6 | BCD; primary ARQC input |
| 9F03 | Amount, Other (Numeric) | Terminal | n 12 | 6 | BCD; cashback |
| 9F04 | Amount, Other (Binary) | Terminal | b | 4 | Binary cashback amount |
| 9F05 | Application Discretionary Data | ICC | b | 1–32 | Issuer/PS application data |
| 9F06 | Application Identifier (AID) — terminal | Terminal | b | 5–16 | AID selected by terminal |
| 9F07 | Application Usage Control | ICC | b | 2 | Geographic/service restrictions |
| 9F08 | Application Version Number (card) | ICC | b | 2 | PS-assigned version |
| 9F09 | Application Version Number (terminal) | Terminal | b | 2 | PS-assigned version |
| 9F0A | Application Selection Registered Proprietary Data (ASRPD) | Card | b | var. | Proprietary data for application selection |
| 9F0B | Cardholder Name Extended | ICC | ans | 27–45 | Extended name >26 chars |
| 9F0C | Issuer Identification Number Extended (IINE) | ICC | n 6 or 8 | 3 or 4 | 6- or 8-digit IIN; may coexist with tag 42 |
| 9F0D | Issuer Action Code — Default (IAC-Default) | ICC | b | 5 | Conditions for offline decline |
| 9F0E | Issuer Action Code — Denial (IAC-Denial) | ICC | b | 5 | Conditions for hard decline |
| 9F0F | Issuer Action Code — Online (IAC-Online) | ICC | b | 5 | Conditions for online attempt |
| 9F10 | Issuer Application Data (IAD) | ICC | b | ≤32 | Proprietary; scheme-specific encoding; ARQC input |
| 9F11 | Issuer Code Table Index | ICC | n 2 | 1 | ISO 8859 charset index for preferred name |
| 9F12 | Application Preferred Name | ICC | ans | 1–16 | Name in national character set |
| 9F13 | Last Online ATC Register | ICC | b | 2 | ATC at last online transaction |
| 9F14 | Lower Consecutive Offline Limit (LCOL) | ICC | b | 1 | Offline floor transaction count |
| 9F15 | Merchant Category Code (MCC) | Terminal | n 4 | 2 | ISO 8583:1993 Card Acceptor Business Code |
| 9F16 | Merchant Identifier | Terminal | ans 15 | 15 | Combined with Acquirer ID = unique merchant |
| 9F17 | PIN Try Counter | ICC | b | 1 | Remaining PIN attempts |
| 9F18 | Issuer Script Identifier | Issuer | b | 4 | Identifies issuer script |
| 9F19 | Token Requestor ID | ICC | n 11 | 6 | Token requestor per EMV Payment Tokenisation Framework |
| 9F1A | Terminal Country Code | Terminal | n 3 | 2 | ISO 3166-1 numeric; ARQC input |
| 9F1B | Terminal Floor Limit | Terminal | b | 4 | Amount threshold for offline authorisation |
| 9F1C | Terminal Identification (TID) | Terminal | an 8 | 8 | Unique terminal ID at merchant |
| 9F1D | Terminal Risk Management Data | Terminal | b | 1–8 | Application-specific risk management |
| 9F1E | Interface Device (IFD) Serial Number | Terminal | an 8 | 8 | Manufacturer-assigned serial |
| 9F1F | Track 1 Discretionary Data | ICC | ans | var. | Discretionary part of Track 1 (ISO/IEC 7813) |
| 9F20 | Track 2 Discretionary Data | ICC | cn | var. | Discretionary part of Track 2 |
| 9F21 | Transaction Time | Terminal | n 6 (HHMMSS) | 3 | Local time of authorisation |
| 9F22 | Certification Authority Public Key Index (terminal) | Terminal | b | 1 | CA key index at terminal |
| 9F23 | Upper Consecutive Offline Limit (UCOL) | ICC | b | 1 | Offline ceiling transaction count |
| 9F24 | Payment Account Reference (PAR) | ICC | an 29 | 29 | Non-financial PAN token linkage (Tokenisation Framework) |
| 9F25 | Last 4 Digits of PAN | ICC | n 4 | 2 | Per EMV Payment Tokenisation Framework |
| 9F26 | Application Cryptogram | ICC | b | 8 | ARQC, TC, or AAC value; primary APC target |
| 9F27 | Cryptogram Information Data (CID) | ICC | b | 1 | Upper nibble: 80=ARQC, 40=TC, 00=AAC |
| 9F2D | ICC PIN Encipherment PK Certificate (RSA) / ICC PK Certificate for ODE (ECC) | ICC | b | var. | For PIN encipherment or biometric encipherment |
| 9F2E | ICC PIN Encipherment Public Key Exponent | ICC | b | 1 or 3 | |
| 9F2F | ICC PIN Encipherment Public Key Remainder | ICC | b | var. | |
| 9F32 | Issuer Public Key Exponent | ICC | b | 1 or 3 | Used for SSAD/ICC cert verification |
| 9F33 | Terminal Capabilities | Terminal | b | 3 | Card data input / CVM / security features bitmap |
| 9F34 | CVM Results | Terminal | b | 3 | Result of CVM processing; ARQC input |
| 9F35 | Terminal Type | Terminal | n 2 | 1 | Environment and communications capability code |
| 9F36 | Application Transaction Counter (ATC) | ICC | b | 2 | Monotonic counter; ARQC input; Book 2 session key input |
| 9F37 | Unpredictable Number | Terminal | b | 4 | Terminal random nonce; ARQC input |
| 9F38 | Processing Options Data Object List (PDOL) | ICC | b | var. | Tags requested by card in GET PROCESSING OPTIONS |
| 9F39 | POS Entry Mode | Terminal | n 2 | 1 | ISO 8583:1987 POS entry method code |
| 9F3A | Amount, Reference Currency | Terminal | b | 4 | Amount in reference currency |
| 9F3B | Application Reference Currency | ICC | n 3 | 2–8 | 1–4 ISO 4217 codes (3 digits each) |
| 9F3C | Transaction Reference Currency Code | Terminal | n 3 | 2 | Reference currency for conversion |
| 9F3D | Transaction Reference Currency Exponent | Terminal | n 1 | 1 | Decimal places for reference currency |
| 9F40 | Additional Terminal Capabilities | Terminal | b | 5 | Extended terminal features bitmap |
| 9F41 | Transaction Sequence Counter | Terminal | n 4–8 | 2–4 | Increments per transaction |
| 9F42 | Application Currency Code | ICC | n 3 | 2 | ISO 4217; card application currency |
| 9F43 | Application Reference Currency Exponent | ICC | n 1 | 1–4 | One exponent per reference currency |
| 9F44 | Application Currency Exponent | ICC | n 1 | 1 | Decimal places for application currency |
| 9F45 | Data Authentication Code | ICC | b | 2 | Issuer-assigned SDA check value |
| 9F46 | ICC Public Key Certificate | ICC | b | var. | Card RSA or ECC public key cert |
| 9F47 | ICC Public Key Exponent | ICC | b | 1 or 3 | |
| 9F48 | ICC Public Key Remainder | ICC | b | var. | |
| 9F49 | Dynamic Data Authentication Data Object List (DDOL) | ICC | b | ≤252 | DOL for INTERNAL AUTHENTICATE |
| 9F4A | Static Data Authentication Tag List | ICC | — | var. | Tags included in SSAD |
| 9F4B | Signed Dynamic Application Data (SDAD) | ICC | b | N_IC | DDA/CDA signature |
| 9F4C | ICC Dynamic Number | ICC | b | 2–8 | Card-generated nonce for DDA/CDA |
| 9F4D | Log Entry | ICC | b | 2 | SFI + max records for transaction log |
| 9F4E | Merchant Name and Location | Terminal | ans | var. | |
| 9F4F | Log Format | ICC | b | var. | DOL for transaction log record |
| A5 | FCI Proprietary Template | ICC | var. | var. | Proprietary FCI per ISO/IEC 7816-4 |
| BF0C | FCI Issuer Discretionary Data | ICC | var. | ≤222 | Issuer discretionary FCI; constructed |

#### Biometric Tags (added in Book 3 v4.4)

| Tag | Name | Source | Fmt | Length | Notes |
|-----|------|--------|-----|--------|-------|
| 7F60 | Biometric Information Template (BIT) | Card/Terminal | b | var. | Nested under BF4A, BF4B, or standalone; defined in ISO/IEC 19785-3 |
| 9F30 | Biometric Terminal Capabilities | Terminal | b | 3 | Indicates biometric CVM capabilities |
| 9F31 | Card BIT Group Template | Card | b | var. | Container for BITs on card |
| A1 | Biometric Header Template (BHT) | Card/Terminal | b | var. | Nested inside 7F60; from ISO/IEC 19785-3 |
| BF4A | Offline BIT Group Template | Card | b | var. | Offline biometric BITs; nested under 9F31 |
| BF4B | Online BIT Group Template | Card | b | var. | Online biometric BITs; nested under 9F31 |
| BF4C | Biometric Try Counters Template | Card | b | var. | Contains per-modality try counters |
| BF4D | Preferred Attempts Template | Card | b | var. | Contains per-modality preferred attempt counts |
| BF4E | Biometric Verification Data Template | Terminal | b | var. | TLV values for VERIFY command |
| DF50 | Facial Try Counter / Preferred Facial Attempts / Enciphered Biometric Key Seed | Card | b | 1 / 1 / var. | Interpretation depends on parent (BF4C / BF4D / BF4E) |
| DF51 | Finger Try Counter / Preferred Finger Attempts / Enciphered Biometric Data | Card | b | 1 / 1 / var. | |
| DF52 | Iris Try Counter / Preferred Iris Attempts / MAC of Enciphered Biometric Data | Card | b | 1 / 1 / 8 | |
| DF53 | Palm Try Counter / Preferred Palm Attempts | Card | b | 1 / 1 | |
| DF54 | Voice Try Counter / Preferred Voice Attempts | Card | b | 1 / 1 | |

Format codes: b=binary, n=numeric (BCD), an=alphanumeric, ans=alphanumeric+special, cn=compressed numeric, var.=variable length

### Scheme and Kernel Proprietary Tags (not in Book 3)

These are defined by payment schemes or contactless kernel specifications, not by EMVCo Book 3.
Sources: Mastercard M/Chip, Visa, EMV Contactless Book C kernels.

| Tag | Name | Owner | Fmt | Length | Notes |
|-----|------|-------|-----|--------|-------|
| 56 | Track 1 Data | Legacy mag-stripe | B | ≤76 | Not an ICC data object; ISO/IEC 7813 Track 1 |
| 9F51 | Application Currency Code | Mastercard | N | 2 | M/Chip-specific |
| 9F52 | Card Verification Results | Mastercard | B | 6 | M/Chip issuer proprietary |
| 9F53 | Consecutive Transaction Counter International Limit | Mastercard | B | 1 | M/Chip CTLI |
| 9F54 | Cumulative Total Transaction Amount | Mastercard | B | 6 | M/Chip accumulator |
| 9F55 | Geographic Indicator | Mastercard | B | 1 | Domestic vs international indicator |
| 9F56 | Issuer Authentication Indicator | Mastercard | B | var. | Mastercard proprietary |
| 9F57 | Issuer Country Code | Mastercard | B | 2 | Binary country code |
| 9F58 | Lower Consecutive Offline Limit (International) | Mastercard | B | 1 | International floor count |
| 9F59 | Upper Consecutive Offline Limit (International) | Mastercard | B | 1 | International ceiling count |
| 9F5A | Application Program Identifier | Mastercard/Kernel | B | 9 | Program ID for contactless kernel selection |
| 9F5C | Cumulative Total Transaction Amount Upper Limit | Mastercard | B | 6 | M/Chip CTTAUL |
| 9F6C | Card Transaction Qualifiers (CTQ) | Visa/Kernel 3 | B | 2 | Contactless card qualifiers bitmap |
| 9F6D | Mag-Stripe Application Version Number | Visa | B | 2 | Contactless mag-stripe version |
| 9F6E | Form Factor Indicator / Third Party Data | Visa | B | 8 | Device type indicator |
| 9F74 | VLP Authorisation Code | Visa | B | 6 | Visa Low-Value Payment auth code |
| 9F7C | Customer Exclusive Data | Visa | B | 32 | Issuer proprietary; card-specific |
| DF01 | Reference Control Parameter | Contactless kernel | B | 1 | Kernel reference parameter |

### ARQC Core Input Tags (most relevant for APC VerifyAuthRequestCryptogram)

The following tags are the primary inputs to ARQC computation per EMV Book 2:
`9F02` (amount) · `9F03` (other amount) · `9F1A` (terminal country) · `95` (TVR) ·
`5F2A` (currency) · `9A` (date) · `9C` (tx type) · `9F37` (unpredictable number) ·
`9F36` (ATC) · `9F10` (IAD, scheme-specific portion)

Result tags: `9F26` (cryptogram value) · `9F27` (CID — type: ARQC/TC/AAC)

---

## EMV Issuer Cryptography

Source: EMV Integrated Circuit Card Specifications for Payment Systems, Book 2 — Security and Key Management, v4.3 (November 2011) and v4.4 (November 2023) (EMVCo). Entries use v4.3 structure; v4.4 corrections applied to algorithm constraints (Bulletin 208, ECC additions).

### EMV RSA Key Hierarchy

```yaml
id: concept.emv-rsa-key-hierarchy
entity_type: concept
canonical_name: EMV RSA Key Hierarchy
aliases:
  - EMV PKI
  - EMV public key infrastructure
summary: Three-level RSA certificate chain used for offline card authentication — CA root keys stored in terminals, Issuer Public Key certified by CA, ICC Public Key certified by Issuer.
domain:
  - emv
  - cryptography
attributes:
  levels:
    CA:
      role: Trust anchor; public key stored in terminals indexed by RID + CA PK Index
      terminal_storage: Minimum 6 CA public keys per RID
      key_size: Up to 248-byte (1984-bit) modulus
      exponent: Must be 3 or 65537 (2^16+1)
    Issuer:
      role: Certified by CA; signs ICC certificates and SSAD (SDA)
      modulus_constraint: N_I <= N_CA
    ICC:
      role: Certified by Issuer; used for dynamic signature generation (DDA/CDA)
      modulus_constraint: N_IC <= N_I
      also: PIN Encipherment Key (PE) modulus constraint N_PE <= N_I
  certificate_format:
    header_byte: "6A"
    format_bytes: "02 (Issuer cert) or 03 (ICC cert)"
    issuer_identifier: Leftmost 3–8 digits of PAN
    expiry: MMYY
    serial_number: 3 bytes assigned by CA
    hash_algorithm_indicator: "01 = SHA-1"
    key_algorithm_indicator: "01 = RSA"
    hash: 20-byte SHA-1 over certificate content
    trailer_byte: "BC"
  certification_revocation_list:
    keyed_by: RID + CA PK Index + Certificate Serial Number
    minimum_entries: 30 per RID
    distribution: Acquirer pushes updates to terminals
  offline_auth_methods:
    SDA: Issuer signs static application data (SSAD); card carries Issuer PK cert + SSAD
    DDA: ICC generates dynamic signature over terminal-provided unpredictable number
    CDA: DDA combined with GENERATE AC — ICC signs cryptogram + dynamic data together
  algorithms:
    v4_3: RSA only; SHA-1 only (indicator 0x01)
    v4_4_additions: "ECC alternative added — P-256 (primary) and P-521 (contingency) via XDA (Extended Dynamic Authentication, Book 2 Section 12); ECC certificates use SHA-256 (indicator 0x02)"
relationships:
  - type: related_to
    target_id: operation.emv-sda
  - type: related_to
    target_id: operation.emv-dda
  - type: related_to
    target_id: operation.emv-cda
  - type: related_to
    target_id: concept.emv-book2-algorithms
status: active
```

### ARQC Generation

```yaml
id: operation.emv-arqc-generation
entity_type: operation
canonical_name: EMV ARQC Generation
aliases:
  - Application Request Cryptogram generation
  - ICC cryptogram computation
summary: Two-step process in which the ICC derives a transaction session key from its AC master key using the ATC, then computes an 8-byte MAC over a mandatory dataset to produce the ARQC.
domain:
  - emv
  - cryptography
attributes:
  steps:
    1_derive_session_key:
      input: ICC Master Key MK_AC + ATC (Application Transaction Counter)
      method: Common Option (Annex A1.3) — not mandatory; issuers may use alternatives
      session_key: SK_AC
    2_compute_mac:
      input: Recommended minimum dataset (EMV Book 2, Table 26) + SK_AC
      output: 8-byte MAC = ARQC (tag 9F26)
  recommended_minimum_dataset_table_26:
    from_terminal:
      - "9F02: Amount Authorised"
      - "9F03: Amount Other"
      - "9F1A: Terminal Country Code"
      - "95: TVR (Terminal Verification Results) — NOTE: TVR is an INPUT, not the ARQC"
      - "5F2A: Transaction Currency Code"
      - "9A: Transaction Date"
      - "9C: Transaction Type"
      - "9F37: Unpredictable Number"
    from_icc:
      - "82: Application Interchange Profile"
      - "9F36: ATC"
  note: These inputs are the MINIMUM; scheme or issuer profiles may add additional data (e.g., 9F10 IAD)
  arqc_tag: "9F26 (8 bytes)"
  cid_tag: "9F27 — Cryptogram Information Data; encodes type: ARQC=80, TC=40, AAC=00 (upper nibble)"
relationships:
  - type: produces
    target_id: artifact.arqc
  - type: uses
    target_id: operation.emv-ac-session-key-derivation
  - type: related_to
    target_id: concept.emv-master-key-derivation
status: active
```

### AC Session Key Derivation (Common Option)

```yaml
id: operation.emv-ac-session-key-derivation
entity_type: operation
canonical_name: EMV AC Session Key Derivation — Common Option
aliases:
  - EMV session key derivation
  - EMV Annex A1.3
summary: Common method for deriving per-transaction session keys for Application Cryptogram (ARQC/ARPC) and Secure Messaging from an ICC Master Key using a transaction-specific diversification value.
domain:
  - emv
  - cryptography
  - key_management
attributes:
  formula: "KS := F(KM)[R]"
  diversification_value_R:
    for_AC_and_ARPC: "ATC || '00' || '00' || ... (ATC in leftmost 2 bytes, remainder zero-padded to n bytes)"
    for_secure_messaging: "Application Cryptogram || '00' || '00' || '00' (cryptogram in leftmost 8 bytes, zero-padded to n bytes)"
  derivation_by_key_size:
    AES_128:
      condition: "k = 8n, n = 16 (single block)"
      formula: "SK := AES(MK)[R]"
    triple_DES_128_or_AES_192_256:
      condition: "16n >= k > 8n"
      formula: |
        F1 = R0 || R1 || 'F0' || Rn-1
        F2 = R0 || R1 || '0F' || Rn-1
        SK := leftmost k-bits of { ALG(MK)[F1] || ALG(MK)[F2] }
  scope: Same session key SK_AC used for all ARQC-related operations in a single transaction
  note: Common Option is NOT mandatory — issuers may implement alternative derivation methods
  separate_keys:
    - MK_AC → SK_AC (for ARQC computation and ARPC verification)
    - MK_MAC → SK_MAC (for issuer script MAC; diversified using Application Cryptogram, not ATC)
    - MK_ENC → SK_ENC (for issuer script encipherment; diversified using Application Cryptogram)
relationships:
  - type: used_by
    target_id: operation.emv-arqc-generation
  - type: used_by
    target_id: operation.emv-arpc-generation
  - type: used_by
    target_id: operation.emv-secure-messaging
  - type: related_to
    target_id: concept.emv-master-key-derivation
status: active
```

### ARPC Generation

```yaml
id: operation.emv-arpc-generation
entity_type: operation
canonical_name: EMV ARPC Generation
aliases:
  - Application Response Cryptogram generation
  - issuer response cryptogram
summary: Issuer-side operation that produces an ARPC to authenticate the host response to the ICC; two methods defined — Method 1 (8-byte, XOR-then-encrypt) and Method 2 (4-byte MAC with Card Status Update).
domain:
  - emv
  - cryptography
attributes:
  session_key: SK_AC (same key used to verify ARQC)
  method_1:
    output_length: 8 bytes
    algorithm_3DES: |
      X = ARC || 00 00 00 00 00 00  (ARC is 2-byte Authorisation Response Code, zero-padded to 8 bytes)
      Y = ARQC XOR X
      ARPC = 3DES(SK_AC)[Y]
    algorithm_AES: |
      Y = ARQC XOR X  (same X construction)
      ARPC = leftmost 8 bytes of AES(SK_AC)[ Y || Y0 ]   where Y0 = 8 zero bytes
    arc_examples:
      "00": approved
      "05": declined
      "01": refer to card issuer
  method_2:
    output_length: 4 bytes
    inputs:
      - ARQC (8 bytes)
      - CSU: Card Status Update (4 bytes, issuer-defined card lifecycle instructions)
      - Proprietary Auth Data (0–8 bytes, optional)
    formula: "Y = ARQC || CSU || Proprietary Auth Data; ARPC = MAC(SK_AC)[Y] truncated to 4 bytes"
    mac_spec_3DES: "ISO 9797-1 Algorithm 3, s=4"
    mac_spec_AES: "CMAC per ISO 9797-1:2011 Algorithm 5, s=4"
    tag_91_format: "ARPC (4 bytes) || CSU (4 bytes) || Proprietary Auth Data (0–8 bytes)"
    note: Tag 91 (Issuer Authentication Data) carries Method 2 response
  security_rule: |
    ARPC MUST NOT be computed from a received ARQC that fails verification.
    If issuer policy returns ARPC on failure, it must be computed independently — not from the received ARQC.
relationships:
  - type: uses
    target_id: operation.emv-ac-session-key-derivation
  - type: verifies
    target_id: artifact.arqc
  - type: related_to
    target_id: operation.emv-arqc-generation
status: active
```

### ICC Master Key Derivation

```yaml
id: concept.emv-master-key-derivation
entity_type: concept
canonical_name: EMV ICC Master Key Derivation
aliases:
  - ICC Master Key personalization
  - EMV key diversification
summary: Process used during card personalization to derive a card-unique ICC Master Key (MK) from the Issuer Master Key (IMK) using PAN and PAN Sequence Number as diversification data; three options (A, B, C) are defined in EMV Book 2 Annex A1.4.
domain:
  - emv
  - cryptography
  - key_management
attributes:
  inputs:
    - Issuer Master Key (IMK)
    - PAN (Primary Account Number)
    - PAN Sequence Number (1 byte, often 00)
  option_A:
    applies_to: Triple DES only; PAN ≤ 16 significant decimal digits
    steps: |
      1. Y = rightmost 16 decimal digits of (PAN || SeqNo), left-padded with zeros if < 16 digits
      2. ZL = 3DES(IMK)[Y]
      3. ZR = 3DES(IMK)[Y XOR FF FF FF FF FF FF FF FF]
      4. MK = ZL || ZR, each byte adjusted to odd parity
    note: Parity adjustment applied byte-by-byte (odd parity per byte)
  option_B:
    applies_to: Triple DES only; PAN > 16 significant decimal digits
    steps: |
      1. Compute SHA-1 hash of (PAN || SeqNo) → 20-byte X
      2. Decimalize X using table: A→0, B→1, C→2, D→3, E→4, F→5 (hex nibbles → digits)
      3. Extract first 16 decimal digits from decimalized result → Y
      4. Continue with Option A step 2 using Y
  option_C:
    applies_to: AES (128, 192, or 256-bit IMK)
    steps: |
      Concatenate PAN || SeqNo → 16-byte numeric value Y
    AES_128: "MK := AES(IMK)[Y]"
    AES_192_256: |
      MK := leftmost k-bits of { AES(IMK)[Y] || AES(IMK)[Y XOR FF...FF] }
  note: None of these options are mandatory — issuers may implement alternative derivation methods
  per_key_type:
    description: |
      Separate IMK/MK pairs per key function. A card carries distinct master keys for:
        - MK_AC  (application cryptogram — ARQC/ARPC)
        - MK_MAC (secure messaging MAC)
        - MK_ENC (secure messaging encipherment)
      All three derived from their respective IMK using the same Option A/B/C logic.
relationships:
  - type: used_by
    target_id: operation.emv-ac-session-key-derivation
  - type: related_to
    target_id: operation.emv-arqc-generation
  - type: related_to
    target_id: key-type.imk
status: active
```

### EMV Secure Messaging

```yaml
id: operation.emv-secure-messaging
entity_type: operation
canonical_name: EMV Secure Messaging
aliases:
  - issuer script protection
  - SM
summary: Cryptographic protection (integrity via MAC and optionally confidentiality via encryption) applied to issuer script commands delivered through EMV messaging to the ICC after online authorization.
domain:
  - emv
  - cryptography
  - key_management
attributes:
  purpose: Protect issuer commands (PIN change, block/unblock) in transit from host to card
  trigger: Applied after ARQC verification when issuer wishes to modify card state
  session_keys:
    SK_MAC:
      source_key: ICC MAC Master Key (MK_MAC, derived from IMK_MAC via A1.4)
      diversification: Application Cryptogram (ARQC value) via A1.3
    SK_ENC:
      source_key: ICC Encipherment Master Key (MK_ENC, derived from IMK_ENC via A1.4)
      diversification: Application Cryptogram (ARQC value) via A1.3
  format_1:
    indicator: Class byte LSN = 'C'
    structure: "Command data || Tag '8E' || MAC (4–8 bytes)"
    encoding: BER-TLV
    mac_chaining:
      first_command: ARQC (8-byte cipher) or ARQC || zeros (16-byte cipher) prepended to MAC input
      subsequent_commands: Previous MAC output chained as input to next MAC computation
  format_2:
    indicator: Class byte LSN = '4'
    structure: "Command data || MAC (4–8 bytes)"
    encoding: Non-TLV (proprietary)
  encipherment:
    mode: ECB or CBC per ISO/IEC 10116
    padding: "'80' || '00'..." to block boundary
  mac_3DES:
    spec: ISO/IEC 9797-1
    padding: Mandatory '80' padding (method 2)
    iv: Zero IV
    algorithm_1: Final block computed with single DES (H_B unchanged)
    algorithm_3: Final block computed with 3DES
    output: Leftmost s bytes
  mac_AES:
    spec: CMAC per ISO/IEC 9797-1:2011 Algorithm 5
    subkeys: K1 and K2 derived from AES(SK)[00...00]
    padding: Not required if message is a multiple of 16 bytes
  common_script_commands:
    - PUT DATA (card parameter update)
    - CHANGE PIN (offline PIN update, Format 2 typically)
    - BLOCK / UNBLOCK application
relationships:
  - type: uses
    target_id: operation.emv-ac-session-key-derivation
  - type: related_to
    target_id: operation.emv-issuer-script
  - type: related_to
    target_id: concept.emv-master-key-derivation
  - type: related_to
    target_id: operation.offline-pin-update
status: active
```

### EMV Approved Algorithms (Book 2, v4.4)

```yaml
id: concept.emv-book2-algorithms
entity_type: concept
canonical_name: EMV Book 2 Approved Algorithms (v4.4)
summary: Algorithm constraints defined in EMV Book 2 Annex B; v4.4 adds ECC (P-256/P-521 via XDA/ODE), SHA-256/SHA-512, and corrects RSA modulus size limits — Issuer and ICC max is 247 bytes (not 248) per Bulletin 208.
domain:
  - emv
  - cryptography
attributes:
  symmetric:
    triple_DES:
      key_length: 128-bit double-length key (two independent 56-bit keys)
      standard: ISO/IEC 18033-3
      single_DES_restriction: Approved ONLY as the final-block MAC algorithm (ISO 9797-1 Algorithm 3 last block); NOT for standalone encryption
    AES:
      key_lengths: [128, 192, 256]
      approved_for: Session key derivation, ARQC/ARPC, secure messaging
  asymmetric:
    RSA:
      public_exponent: Must be 3 or 65537 (2^16+1)
      max_modulus_bytes_Table43:
        CA:                  248 bytes (1984 bits)
        Issuer_SDA_mode:     248 bytes
        Issuer:              247 bytes (1976 bits)
        ICC:                 247 bytes
        ICC_PIN_encipherment: 247 bytes
        note: "Bulletin 208 corrected the v4.3 table; Issuer/ICC caps are 247 bytes, not 248"
      key_size_constraints:
        - "N_IC <= N_I <= N_CA  (ICC modulus <= Issuer modulus <= CA modulus)"
        - "N_PE <= N_I          (PIN Encipherment key modulus <= Issuer modulus)"
    ECC:
      added_in: v4.4
      curves:
        primary:
          name: P-256
          N_FIELD: 32 bytes
          spec: FIPS 186-4
          equation: "y² = x³ − 3x + b over F_p (prime field)"
          used_for: XDA offline authentication (Book 2 Section 12), ODE PIN encipherment (Section 13)
        contingency:
          name: P-521
          N_FIELD: 66 bytes
          spec: FIPS 186-4
      public_key_encoding: x-coordinate only (N_FIELD bytes); receiving party recovers y from curve equation
  hashing_Table47:
    "0x01":
      algorithm: SHA-1
      output: 20 bytes
      approved_for: RSA operations only (legacy; NOT permitted for ECC)
    "0x02":
      algorithm: SHA-256
      output: 32 bytes
      approved_for: ECC primary; also permitted for RSA
    "0x03":
      algorithm: SHA-512
      output: 64 bytes
      approved_for: ECC contingency (P-521)
    "0x80":
      algorithm: SM3
      output: 32 bytes
      approved_for: Scheme-specific / proprietary
  ECC_algorithm_suites:
    signature_Table48:
      "0x10":
        description: EC-SDSA + SHA-256 + P-256  (primary XDA suite)
      "0x13":
        description: EC-SDSA + SHA-512 + P-521  (contingency)
    encryption_Table49:
      "0x00":
        description: P-256 + ECDH + Encrypt-then-MAC (EtM) + AES  (primary ODE suite)
relationships:
  - type: related_to
    target_id: concept.emv-rsa-key-hierarchy
  - type: related_to
    target_id: operation.emv-arqc-generation
status: active
```

---

## Thales payShield Migration Reference

### KSN Descriptor Encoding (DUKPT)

```yaml
id: concept.thales-ksn-descriptor
entity_type: data_element
canonical_name: KSN Descriptor
aliases:
  - KSN descriptor
  - key_set_id_length + sub_key_id_length + device_id_length
summary: >
  A 3-digit numeric string stored alongside the BDK in Thales payShield HSM user storage.
  Tells the HSM how many digits of the KSN represent each logical sub-field.
  Required for all DUKPT key derivation commands that take a BDK reference.
domain:
  - key_management
  - hsm
  - pin_processing
attributes:
  format: 3 ASCII decimal digits "[key_set_id_len][sub_key_id_len][device_id_len]"
  total_constraint: "sum of three digits must equal the total KSN length in digits"
  standard_value_64bit_ksn:
    descriptor: "605"
    breakdown:
      key_set_id_len: 6
      sub_key_id_len: 0
      device_id_len: 5
    notes: >
      Standard X9.24-1:2009 (TDES DUKPT) 10-byte (80-bit) KSN encodes
      6 digits key_set_id, 0 digits sub_key_id, 5 digits device_id.
      Total = 11 hex digits (44 bits used in practice).
  commands_that_use_descriptor:
    - CK  # Derive current DUKPT working key
    - CM  # Decrypt PIN using DUKPT working key
    - G0  # Derive DUKPT working key and translate PIN
    - CI  # Derive DUKPT working key (generic)
    - GW  # Derive DUKPT working key and re-encrypt data
    - M0  # Generate DUKPT MAC
    - M2  # Verify and translate DUKPT MAC
    - M4  # Generate DUKPT response MAC
  aes_dukpt_ksn_length: 24 bytes (48 hex digits); descriptor encoding follows same pattern but with larger sub-fields
  storage: stored in the HSM command as a literal 3-char field immediately after the BDK identifier
constraints:
  - The descriptor must be agreed between the BDK-injector (terminal manufacturer / key-injection facility) and the acquirer host before key injection
  - Misconfigured descriptor causes invalid key derivation silently — KSN parses, wrong key derived
  - For AES DUKPT, the KSN is 24 bytes; payShield requires Key Block LMK (not Variant LMK) to protect the AES BDK
relationships:
  - type: related_to
    target_id: concept.dukpt
  - type: related_to
    target_id: concept.ksn
  - type: related_to
    target_id: concept.thales-bdk-types
status: active
```

### Thales Key Names → Variant LMK Codes → TR-31 / APC Usage Codes

```yaml
id: concept.thales-key-type-mapping
entity_type: reference_list
canonical_name: Thales payShield Key Type Code Cross-Reference
aliases:
  - Variant LMK key type codes
  - Key Block and Variant Comparison Table
summary: >
  Maps Thales payShield key names to their Variant LMK 3-digit type codes, LMK pair/variant,
  TR-31 Key Block usage codes, and APC TR31_* key usage constants.
  Source: payShield 10K Host Programmer's Manual PUGD0541-003 pages 98 and 113-114.
domain:
  - key_management
  - hsm
attributes:
  table:
    # Format: key_name: {variant_code, lmk_pair, variant_nibble, kb_code, apc_usage}
    ZMK:
      variant_code: "000"
      lmk_pair: "04-05"
      variant: "0"
      kb_code: K0 / 52
      apc_usage: TR31_K0_KEY_ENCRYPTION_KEY
      description: Zone Master Key — used to encrypt ZPKs for key exchange between acquirer and processor
    ZPK:
      variant_code: "001"
      lmk_pair: "06-07"
      variant: "0"
      kb_code: P0 / 71
      apc_usage: TR31_P0_PIN_ENCRYPTION_KEY
      description: Zone PIN Key — encrypts PIN blocks for inter-zone PIN routing
    PVK_PVVK:
      variant_code: "002"
      lmk_pair: "14-15"
      variant: "0"
      kb_code: "V0 / V1 / V2"
      apc_usage: "TR31_V1_IBM3624_PIN_VERIFICATION_KEY or TR31_V2_VISA_PIN_VERIFICATION_KEY"
      description: PIN Verification Key — IBM 3624 (V1) or Visa PVV (V2)
    TAK:
      variant_code: "003"
      lmk_pair: "16-17"
      variant: "0"
      kb_code: "M0 / M1 / M3 / M5 / M6"
      apc_usage: "TR31_M3_ISO_9797_3_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY"
      description: Terminal Authentication Key — MAC key between terminal and host
    WWK:
      variant_code: "006"
      lmk_pair: "22-23"
      variant: "0"
      kb_code: "01"
      apc_usage: no direct APC equivalent
      description: Watchword Key — HSM-specific authentication; no APC equivalent
    ZAK:
      variant_code: "008"
      lmk_pair: "26-27"
      variant: "0"
      kb_code: "M0 / M1 / M3 / M5 / M6"
      apc_usage: "TR31_M3_ISO_9797_3_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY"
      description: Zone Authentication Key — MAC key for inter-zone message authentication
    BDK_1:
      variant_code: "009"
      lmk_pair: "28-29"
      variant: "0"
      kb_code: B0
      apc_usage: TR31_B0_BASE_DERIVATION_KEY
      description: Base Derivation Key type 1 — standard bidirectional X9.24-1 DUKPT
    HMAC:
      variant_code: "10C"
      lmk_pair: "34-35"
      variant: "1"
      kb_code: "61-65"
      apc_usage: TR31_M7_HMAC_KEY
      description: HMAC key
    ZEK:
      variant_code: "00A"
      lmk_pair: "30-31"
      variant: "0"
      kb_code: "D0 / 22"
      apc_usage: TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY
      description: Zone Encryption Key — inter-zone data encryption
    DEK_or_TEK_AS2805:
      variant_code: "00B"
      lmk_pair: "32-33"
      variant: "0"
      kb_code: "D0 / 21"
      apc_usage: TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY
      description: Data Encryption Key or Terminal Encryption Key (AS2805)
    KEK:
      variant_code: "107"
      lmk_pair: "24-25"
      variant: "1"
      kb_code: "54"
      apc_usage: TR31_K1_KEY_BLOCK_PROTECTION_KEY
      description: Key Encryption Key — wraps other keys for transport (prefer K1 for new deployments)
    MK_AC:
      variant_code: "109"
      lmk_pair: "28-29"
      variant: "1"
      kb_code: E0
      apc_usage: TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS
      description: EMV Application Cryptogram Master Key (ARQC/ARPC only — NOT for PIN change scripts)
    MK_SMI:
      variant_code: "209"
      lmk_pair: "28-29"
      variant: "2"
      kb_code: E2
      apc_usage: TR31_E2_EMV_MKEY_INTEGRITY
      description: EMV Secure Messaging Integrity Master Key — script MAC generation
    MK_SMC:
      variant_code: "309"
      lmk_pair: "28-29"
      variant: "3"
      kb_code: E1
      apc_usage: TR31_E1_EMV_MKEY_CONFIDENTIALITY
      description: EMV Secure Messaging Confidentiality Master Key — script encryption
    MK_DAC:
      variant_code: "409"
      lmk_pair: "28-29"
      variant: "4"
      kb_code: E3
      apc_usage: TR31_E3_EMV_MKEY_OTHER (if supported) or no direct APC equivalent
      description: Dynamic Authentication Code Master Key
    MK_DN:
      variant_code: "509"
      lmk_pair: "28-29"
      variant: "5"
      kb_code: E4
      apc_usage: TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS
      description: Dynamic Number Master Key (iCVV etc.)
    BDK_2:
      variant_code: "609"
      lmk_pair: "28-29"
      variant: "6"
      kb_code: "41"
      apc_usage: TR31_B0_BASE_DERIVATION_KEY
      description: BDK type 2 — acquirer-only unidirectional DUKPT; 5 key types derivable
    BDK_3:
      variant_code: "809"
      lmk_pair: "28-29"
      variant: "8"
      kb_code: "42"
      apc_usage: TR31_B0_BASE_DERIVATION_KEY
      description: BDK type 3 — data-only (no PIN/MAC) bidirectional; not X9.24-1 compliant
    BDK_4:
      variant_code: "909"
      lmk_pair: "28-29"
      variant: "9"
      kb_code: "43"
      apc_usage: TR31_B0_BASE_DERIVATION_KEY
      description: BDK type 4 — PSP/gateway terminal role unidirectional DUKPT; 5 key types
    IKEY:
      variant_code: "302"
      lmk_pair: "14-15"
      variant: "3"
      kb_code: B1
      apc_usage: TR31_B1_BASE_DERIVATION_KEY_VARIANT_2 (if supported)
      description: Initial Key — injected into terminal during key injection; deleted by terminal after initialization
    CVK:
      variant_code: "402"
      lmk_pair: "14-15"
      variant: "4"
      kb_code: "C0 / 12 / 13"
      apc_usage: TR31_C0_CARD_VERIFICATION_KEY
      description: Card Verification Key — CVV, CVV2, iCVV
    PVK_as_PEK:
      variant_code: "70D"
      lmk_pair: "14-15"
      variant: "7"
      kb_code: "P0 / 71"
      apc_usage: TR31_P0_PIN_ENCRYPTION_KEY
      description: PIN Encryption Key (PEK / Acquirer Working Key) — when used as an acquirer-side PEK
    TPK:
      variant_code: "002 or 70D"
      kb_code: "P0 / 71"
      apc_usage: TR31_P0_PIN_ENCRYPTION_KEY
      description: Terminal PIN Key — encrypts PINs between terminal and acquirer host
    TMK:
      variant_code: "002 or 80D"
      kb_code: "K0 / 51"
      apc_usage: TR31_K0_KEY_ENCRYPTION_KEY
      description: Terminal Master Key — wraps TPK/TAK for download to terminal
    TKR:
      variant_code: "002 or 90D"
      kb_code: "P0 / 73"
      apc_usage: TR31_P0_PIN_ENCRYPTION_KEY
      description: Terminal Key for Retail — variant naming in some Thales configurations
    TEK:
      variant_code: "30B"
      lmk_pair: "32-33"
      variant: "3"
      kb_code: "D0 / 23"
      apc_usage: TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY
      description: Terminal Encryption Key — encrypts data between terminal and host
constraints:
  - Migration note: When exporting from payShield for APC import, use TR-31 Key Block format. The Variant LMK code alone does not convey TR-31 attributes — the Key Block wrapping adds usage, algorithm, and mode-of-use attributes that APC enforces.
  - APC does not support Variant LMK directly. Keys must be exported as TR-31 Key Blocks from payShield before import to APC.
  - E0 (MK-AC) is ARQC/ARPC only. PIN change script MAC uses E2 (MK-SMI). PIN change script encryption uses E1 (MK-SMC). Common migration error.
relationships:
  - type: related_to
    target_id: concept.thales-ksn-descriptor
  - type: related_to
    target_id: concept.thales-bdk-types
  - type: related_to
    target_id: concept.lmk-vs-apc
status: active
```

### Thales BDK Type Taxonomy (BDK-1 through BDK-5)

```yaml
id: concept.thales-bdk-types
entity_type: reference_list
canonical_name: Thales DUKPT BDK Type Taxonomy
aliases:
  - BDK-1
  - BDK-2
  - BDK-3
  - BDK-4
  - BDK-5
  - Thales BDK types
summary: >
  Thales payShield 10K uses five BDK types, each with a distinct Variant LMK code and Key Block code.
  All map to TR31_B0_BASE_DERIVATION_KEY in APC, but differ in which derived key types are supported
  and in terminal directionality. Source: PUGD0541-003 pages 97-98.
domain:
  - key_management
  - hsm
  - pin_processing
attributes:
  bdk_1:
    variant_code: "009"
    kb_code: B0
    algorithm: T (TDES) or A (AES, Key Block only)
    direction: Bidirectional (acquirer and terminal can both encrypt/decrypt)
    x9_24_1_compliant: true
    derived_key_types:
      - PIN Encryption Key (PEK)
      - Data Encryption Key (DEK)
      - MAC generation key
      - MAC response key
      - PIN verification key
    use_case: Standard acquirer DUKPT — most common; required if terminal supports both PIN and data DUKPT
    notes: Default for new deployments
  bdk_2:
    variant_code: "609"
    kb_code: "41"
    direction: Unidirectional (acquirer receive only)
    x9_24_1_compliant: false
    derived_key_types: 5 (same set as BDK-1 except response key)
    use_case: Acquirer-side only; terminal cannot encrypt responses
    notes: Use when terminals are single-direction only
  bdk_3:
    variant_code: "809"
    kb_code: "42"
    direction: Bidirectional
    x9_24_1_compliant: false
    derived_key_types: Data encryption only (no PIN, no MAC)
    use_case: Data-only DUKPT without PIN/MAC key derivation
    notes: Not compliant with X9.24-1 — non-standard deployment only
  bdk_4:
    variant_code: "909"
    kb_code: "43"
    direction: Unidirectional
    x9_24_1_compliant: false
    derived_key_types: 5
    use_case: PSP or gateway acting in terminal role — receives encrypted data, not terminal-side
    notes: Same as BDK-2 but from the gateway/PSP perspective
  bdk_5:
    variant_code: none (Key Block only)
    kb_code: "44"
    direction: Bidirectional (like BDK-1)
    x9_24_1_compliant: false
    derived_key_types: Same as BDK-1 with different IKEY derivation
    use_case: Italian payment network (Bancomat / SPE-DEF-041-112)
    notes: Not available on all payShield configurations; requires Italian network option
  ikey:
    variant_code: "302"
    kb_code: B1
    description: Initial Key — the per-terminal derived key injected into the terminal by the key injection facility. Deleted by the terminal after successful initialization. Derived from the BDK using the terminal's KSN.
apc_mapping:
  note: All BDK types map to TR31_B0_BASE_DERIVATION_KEY in APC. The directional and derived-key-type distinctions are properties of the DUKPT protocol implementation, not separately enforced by APC key usage.
constraints:
  - BDK-3 is not X9.24-1 compliant — verify with counterparty before deploying
  - BDK-5 requires Italian network license on payShield; no direct APC equivalent for the IKEY derivation variant
  - AES DUKPT BDK must be in an AES Key Block (KB code requires AES Key Block LMK); Variant LMK cannot protect AES BDKs on payShield
relationships:
  - type: related_to
    target_id: concept.dukpt
  - type: related_to
    target_id: concept.thales-key-type-mapping
  - type: related_to
    target_id: concept.thales-ksn-descriptor
status: active
```

### LMK Concept and APC Migration Equivalent

```yaml
id: concept.lmk-vs-apc
entity_type: concept
canonical_name: Local Master Key (LMK) and APC Migration Equivalence
aliases:
  - LMK
  - Local Master Key
  - Master File Key
summary: >
  The LMK is the root key protecting all keys stored in a Thales payShield HSM.
  Keys are stored as LMK-encrypted blobs (ciphertext values) in the host application or database.
  These blobs cannot be imported directly into APC. Migration requires exporting from payShield in
  TR-31 or TR-34 format first, then importing into APC.
domain:
  - key_management
  - hsm
  - cryptography
attributes:
  lmk_description:
    definition: >
      The LMK is a set of TDES key pairs (20 pairs, labelled 00-39 in Variant scheme) or a single
      256-bit AES key (Key Block scheme) that the HSM uses to encrypt all keys stored outside the HSM's
      secure boundary. The host application stores the encrypted ciphertext (the "key blob"), not the key itself.
    two_schemes:
      variant_lmk:
        algorithm: TDES (always)
        key_pairs: 20 (LMK pair 00-01 through 38-39)
        key_separation: XOR variant applied before/after encryption; variant nibble in type code (e.g. 009 = LMK28-29 variant 0)
        blob_format: raw ciphertext (no integrity, no attribute binding)
        weakness: >
          No cryptographic binding of key attributes to the ciphertext. A key can be
          re-labeled (type code changed) by a compromised host without HSM detection.
          PCI PIN Req 18-3 prohibited Variant LMK for PIN keys by 1 January 2025.
      key_block_lmk:
        algorithm: TDES or AES-256
        format: TR-31 key block (header + ciphertext + MAC)
        key_separation: TR-31 header attributes (usage, algorithm, mode of use) are authenticated by MAC
        advantage: >
          Attribute binding — the HSM verifies the header MAC before use; a re-labeled
          key block will fail MAC verification. Required for PIN keys per PCI PIN v3.1 Req 18-3.
  apc_equivalent:
    description: >
      APC manages its own equivalent of the LMK internally. There is no concept of an LMK-encrypted blob
      that the host application stores. Instead, APC returns an opaque key ARN (Amazon Resource Name) that
      is used as the key identifier in all API calls. The key material never leaves APC custody.
    migration_implication: >
      LMK-encrypted key blobs stored in a host database or application cannot be imported into APC directly.
      They must first be exported from the payShield in TR-31 or TR-34 format (which re-encrypts under a
      transport key negotiated with APC), then imported into APC using ImportKey.
    import_workflow:
      step_1: Call APC GetParametersForImport to obtain a TR-34 or TR-31 import token and APC's public key
      step_2: On payShield, export the target key as TR-31 under a KEK that was imported from APC's public key (TR-34 KEK), or export as TR-31 under an existing shared ZMK
      step_3: Call APC ImportKey with the TR-31 key block; APC returns a key ARN
      step_4: Replace LMK blob references in host application with APC key ARN
  lmk_rekeying:
    description: >
      payShield supports LMK re-keying (changing the LMK while preserving stored key blobs through
      automated re-encryption). The BW command translates a BDK/IKEY from old LMK to new LMK.
      This concept does not apply to APC — APC manages its own key protection internally.
    apc_equivalent: none; APC handles key protection rotation internally without host involvement
constraints:
  - Never attempt to import a raw LMK-encrypted blob into APC. It will fail (wrong wrapping, wrong format) or — if accidentally treated as TR-31 — produce a silently wrong key.
  - Variant LMK keys for PIN encryption are prohibited by PCI PIN v3.1 Req 18-3 from 1 January 2025.
  - AES BDKs (AES DUKPT) cannot be protected by Variant LMK on payShield; require Key Block LMK.
relationships:
  - type: related_to
    target_id: concept.thales-key-type-mapping
  - type: related_to
    target_id: concept.thales-bdk-types
  - type: related_to
    target_id: concept.dukpt
status: active
```

### AES DUKPT Migration Guide (TDES → AES, X9.24-3:2017)

```yaml
id: concept.aes-dukpt-migration
entity_type: concept
canonical_name: AES DUKPT Migration from TDES DUKPT
aliases:
  - AES DUKPT
  - X9.24-3
  - X9.24-3:2017
  - AES DUKPT migration
summary: >
  Key differences between TDES DUKPT (X9.24-1:2009) and AES DUKPT (X9.24-3:2017) that affect
  migration decisions, HSM command parameters, and APC API calls.
domain:
  - key_management
  - pin_processing
  - hsm
  - cryptography
attributes:
  ksn_length:
    tdes_dukpt: 10 bytes (80 bits) — typically 3 bytes key_set_id + 5 bytes KSN counter; in Thales: 6+0+5 digit descriptor "605"
    aes_dukpt: 24 bytes (192 bits) — 4 bytes key_set_id + 8 bytes device_id + 4 bytes transaction_counter per X9.24-3
  bdk_algorithm:
    tdes_dukpt: TDES (triple-length 3DES, 168-bit nominal / 112-bit effective) — Variant or Key Block LMK
    aes_dukpt: AES-128, AES-192, or AES-256 — requires Key Block LMK (Variant LMK not supported on payShield)
  ipek_terminology:
    tdes_dukpt: IPEK (Initial PIN Encryption Key) — 3DES double-length key derived from BDK + KSN
    aes_dukpt: IK (Initial Key) — AES key; terminology changed in X9.24-3; "IPEK" is not used for AES DUKPT
  pin_block_format:
    tdes_dukpt: ISO Format 0 (most common) or Format 3 — XOR-based, PAN-dependent
    aes_dukpt: ISO Format 4 only — AES-CBC encryption, includes PAN in ciphertext, not XOR-based; payShield format code "48"
    constraint: AES DUKPT mandates Format 4; Format 0/3 are not permitted with AES DUKPT
  key_derivation:
    tdes_dukpt: IPEK derivation from BDK + 10-byte KSN; future key register shift via left/right half operations
    aes_dukpt: >
      AES-CMAC-based key derivation per X9.24-3; derives working keys for: PIN encryption (PEK),
      MAC generation (MAK), data encryption (DEK), key encryption (KEK). Each working key is
      AES-CMAC derived, not a register-shift variant.
  thales_payhsield_command_support:
    aes_dukpt_commands_for_pin: supported via standard DUKPT command set with AES BDK and Format 4 indicator
    unsupported_at_manual_date_aug_2020: "3DES and HMAC key derivation from AES DUKPT not supported (may have been added in later firmware)"
  apc_equivalence:
    bdk_key_type: TR31_B0_BASE_DERIVATION_KEY with algorithm AES_128, AES_192, or AES_256
    pin_translate: TranslatePinData with IncomingDukptAttributes (AES, KSN) + OutgoingAttributes
    pin_format: IsoFormat4 required for AES DUKPT in APC
    ksn_format: 24-byte hex string passed as KSN in API call
constraints:
  - AES DUKPT BDK requires Key Block LMK on payShield — cannot use Variant LMK; migration must account for this
  - All AES DUKPT PIN operations use ISO Format 4 — no exceptions; counterparty must support Format 4
  - If translating from AES DUKPT (Format 4) to a downstream ZPK, ensure the downstream supports Format 4 or translate to Format 0 at the APC/acquirer host (not at the terminal)
  - IPEK terminology is TDES-specific; never use "IPEK" for AES DUKPT (it confuses the derivation scheme); use "IK"
relationships:
  - type: related_to
    target_id: concept.dukpt
  - type: related_to
    target_id: concept.thales-bdk-types
  - type: related_to
    target_id: concept.thales-ksn-descriptor
  - type: related_to
    target_id: concept.lmk-vs-apc
status: active
```

### Thales payShield Wire Protocol Framing (TCP/IP)

```yaml
id: concept.thales-wire-protocol
entity_type: concept
canonical_name: Thales payShield TCP/IP Host Command Wire Protocol
aliases:
  - payShield wire protocol
  - payShield framing
  - payShield TCP framing
summary: >
  The binary framing used to send host commands to and receive responses from a Thales payShield 10K
  over TCP/IP. Essential for proxy and protocol translation work. Source: PUGD0541-003 Chapter 3.
domain:
  - hsm
attributes:
  send_format:
    frame: "[2-byte LENGTH][COMMAND bytes]"
    length_field: big-endian unsigned 16-bit integer; counts COMMAND bytes only, does NOT include the 2-byte length field itself
    no_stx_etx: true
    example: "Command 'NC' with no data: LENGTH=0x00 0x02, COMMAND=0x4E 0x43"
  response_format:
    frame: "[2-byte LENGTH][RESPONSE bytes]"
    response_code_derivation: >
      Response code is two ASCII characters derived from the command code:
      response[0] = command[0] (first char unchanged)
      response[1] = command[1] + 1 (second char ASCII value incremented by 1)
      e.g. command "NC" → response prefix "ND"; command "A0" → response prefix "A1"
  message_structure:
    header: "1–255 ASCII characters; arbitrary; used for session routing or message ID; returned unchanged"
    command_code: "2 ASCII characters (e.g. 'NC', 'A0', 'CA')"
    data: "command-specific parameter fields, positional or length-delimited"
    optional_trailer: "Error Message (EM) byte 0x19 followed by up to 32 ASCII chars of diagnostic text; returned only when response code is '00' (success) or '02' (warning)"
  connection_parameters:
    default_port: 1500
    max_connections: 64 simultaneous sockets
    buffer_size: 32 KB per connection
    encoding_detection: auto-detects ASCII vs EBCDIC per connection
  proxy_implications:
    framing_rule: >
      Proxy must strip the 2-byte LENGTH header before parsing the COMMAND CODE (first 2 bytes
      of the COMMAND field). Re-add the LENGTH header with correct byte count before forwarding.
    response_code_rule: >
      Proxy builds synthetic responses; response code = first char of command + (ASCII value of
      second char + 1). For multi-char error codes within data field, see command-specific docs.
    header_passthrough: proxy should echo the header field unchanged (it is used by some hosts for session correlation)
constraints:
  - LENGTH field covers COMMAND bytes only — do not include the 2 bytes of the LENGTH field itself in the count
  - Response code second character is incremented by 1 in ASCII — e.g. 'C' (0x43) → 'D' (0x44); wrapping behavior at 'Z'/'z' is undefined
  - Max header length 255 bytes; max total frame ~32 KB (buffer limit)
relationships:
  - type: related_to
    target_id: concept.thales-key-type-mapping
status: active
```

### RTKS and Australian AS2805 TKS Command Disambiguation

```yaml
id: concept.thales-rtks-australian-tks
entity_type: concept
canonical_name: Thales RTKS and Australian AS2805 Transaction Key Scheme Commands
aliases:
  - RTKS
  - Racal Transaction Key Scheme
  - Australian TKS
  - AS2805 TKS
  - R* commands
  - H* commands
summary: >
  The payShield 10K supports two transaction key schemes — Racal TKS (RTKS) and Australian AS2805 TKS —
  under the SAME two-character command codes (RI, RK, RM, RO, RQ, RS, RU, RW). The active scheme is
  determined by a security setting on the HSM; the command code meaning changes completely depending
  on which scheme is configured. H* commands (HI, HK, HM, HO, HQ, HS, HU, HW) provide access to
  whichever TKS is NOT the configured default. Source: PUGD0541-003 Chapter 4.
domain:
  - hsm
  - key_management
  - pin_processing
attributes:
  command_disambiguation:
    RI:
      rtks_function: "TX Request with PIN (T/AQ Key) — processes terminal PIN using acquirer key"
      australian_tks_function: "Verify TX Request with PIN when CD Field not Available"
    RK:
      rtks_function: "TX Request Without PIN — authenticates non-PIN transaction request"
      australian_tks_function: "Generate TX Response with Auth Para by Acquirer"
    RM:
      rtks_function: "Administration Request — processes administrative/maintenance transaction"
      australian_tks_function: "Generate TX Response with Auth Para by Card Issuer"
    RO:
      rtks_function: "TX Response with Auth Para from Card Issuer — processes issuer auth response"
      australian_tks_function: "Translate PIN from PEK to ZPK Encryption"
    RQ:
      rtks_function: "Generate Auth Para and TX Response — generates auth parameters for response"
      australian_tks_function: "Verify TX Completion Confirmation"
    RS:
      rtks_function: "Confirmation — confirms transaction completion"
      australian_tks_function: "Generate TX Completion Response"
    RU:
      rtks_function: "TX Request with PIN (T/CI Key) — processes PIN using card issuer key"
      australian_tks_function: "Generate Auth Para at Card Issuer"
    RW:
      rtks_function: "Translate KEYVAL — translates key value between formats"
      australian_tks_function: "Generate Initial Terminal Key"
  h_star_variants:
    description: >
      H* commands (HI, HK, HM, HO, HQ, HS, HU, HW) are identical in function to R* commands
      but access the NON-configured TKS. If the HSM is configured for RTKS, HI accesses Australian TKS function.
      If configured for Australian TKS, HI accesses RTKS function. Used when dual-scheme operation is required.
    mapping:
      HI: mirrors RI (non-configured TKS)
      HK: mirrors RK (non-configured TKS)
      HM: mirrors RM (non-configured TKS)
      HO: mirrors RO (non-configured TKS)
      HQ: mirrors RQ (non-configured TKS)
      HS: mirrors RS (non-configured TKS)
      HU: mirrors RU (non-configured TKS)
      HW: mirrors RW (non-configured TKS)
  apc_equivalence:
    rtks_commands: >
      No direct APC equivalent for RTKS as a transaction key scheme. Equivalent functionality
      is achieved through individual APC operations: TranslatePinData (PIN translation),
      GenerateMac/VerifyMac (authentication), and VerifyPinData (PIN verification).
    australian_tks_commands: >
      AS2805 MAC generation uses TR31_M0_ISO_16609_MAC_KEY in APC. PIN translation
      equivalent: TranslatePinData. No bundled "transaction scheme" abstraction in APC —
      each cryptographic step is a separate API call.
    migration_note: >
      Applications using R*/H* commands must be decomposed into individual operations.
      The TKS abstraction bundles multiple steps (auth + MAC + PIN) into one HSM call.
      APC separation of concerns requires identifying which cryptographic primitive each
      R* command actually performs and mapping to the appropriate APC data-plane operation.
constraints:
  - The function of RI/RK/RM/RO/RQ/RS/RU/RW depends entirely on the HSM security setting (configured TKS). Identify which scheme is active before analyzing any R* command usage.
  - If code uses both R* and H* commands, the application is accessing both TKS schemes simultaneously — extremely rare; requires dual-scheme license.
  - AS2805 MAC key (M0) is the TR-31 key type for Australian TKS MAC operations; not to be confused with retail MAC (M3) or CMAC (M6).
relationships:
  - type: related_to
    target_id: concept.thales-key-type-mapping
  - type: related_to
    target_id: concept.thales-wire-protocol
status: active
```

---

## Thales Legacy Command Wire Formats

### JS Command — ARQC Verification and/or ARPC Generation (UnionPay / CUP)

```yaml
id: concept.thales-js-command
entity_type: command
canonical_name: JS — ARQC Verification and/or ARPC Generation (UnionPay)
aliases:
  - JS command
  - JT response
  - UnionPay ARQC
  - CUP ARQC
  - PBOC ARQC
summary: >
  Thales payShield 10K Legacy Host Command (PUGD0538-003 §7 pp.122-123) for
  ARQC verification and/or ARPC generation for UnionPay (CUP) / PBOC 2.0 / 3.0 cards.
  Response code: JT. License required: PS10-LIC-LEGACY.
  This is distinct from KQ (Core command, PUGD0537-004) which handles Visa/MC ARQC.
domain:
  - hsm
  - emv
  - cryptography
attributes:
  source: "PUGD0538-003 Legacy Host Commands, Revision A, 04 August 2020, §7 pp.121-123 — AUTHORITATIVE"
  lmk_support: "Variant LMK and Key Block LMK"
  scheme: "UnionPay (CUP) only — Scheme ID always '1' (CUP Card Key Derivation, CUP ver4.2)"

  wire_format_command:
    note: "All fields are positional, no delimiters except where noted. Types: H=ASCII hex chars, N=ASCII decimal chars, B=raw binary bytes, A=ASCII char."
    fields:
      - name: Mode Flag
        type: 1H
        details: >
          ASCII hex digit. Values:
          '0' = Perform ARQC verification only (no ARPC generated)
          '1' = Perform ARQC verification AND ARPC generation (ARC required)
          '2' = Perform ARPC generation only (no ARQC verification; no TxnData in wire)
          NOTE: '9' does NOT exist. Mode '2' is valid. Currently unimplemented in proxy — see migration note.
      - name: Scheme ID
        type: 1N
        details: >
          ASCII decimal digit. Only valid value: '1' = CUP Card Key Derivation (CUP ver4.2).
          CRITICAL: This field is PRESENT in JS but ABSENT in KQ. JS has: Mode→SchemeID→Key.
          A proxy reading JS the same as KQ (which goes Mode→SchemeID→KeyType→Key) will
          mis-align every field after Mode Flag.
      - name: "*MK-AC(LMK)"
        type: "32H or 1A+32H"
        details: >
          Issuer Master Key for Application Cryptograms, encrypted under Variant 1 of LMK pair 28-29.
          Encoding: 32 ASCII hex chars (double-length, no prefix) OR one ASCII prefix char ('U' or 'T') + 32H or 48H.
          CRITICAL DIFFERENCE FROM KQ: JS has NO separate 3H Key Type field before the key.
          KQ layout: [KeyType 3H][Key var]. JS layout: [Key var] directly after Scheme ID.
          A proxy that skips 3H as "key type" before the key will consume the first 3 chars of actual key material.
          Use parse_key_32 (base 32H) not parse_legacy_key (base 16H).
      - name: "PAN/PAN Sequence No"
        type: 8B
        details: >
          8 raw binary bytes. Pre-formatted BCD encoding:
          Nibbles 0-11  (bytes 0-5 + high nibble byte 6): rightmost 12 PAN digits
          Nibbles 12-13 (low nibble byte 6 + high nibble byte 7): PAN sequence number
          Nibbles 14-15 (low nibble byte 7): 0xFF padding
          Example: PAN right-12="123456789012", seq="01" → bytes [0x12,0x34,0x56,0x78,0x90,0x12,0x01,0xFF]
          WRONG assumption: treating this as 16N ASCII chars (as in the incorrect proxy stub).
      - name: ATC
        type: 2B
        details: >
          Application Transaction Counter. 2 raw binary bytes, big-endian.
          WRONG assumption: treating as 4H ASCII hex chars. Correct: read 2 bytes, hex-encode for APC.
      - name: "Padding Flag [Modes 0,1 only]"
        type: 1N
        details: >
          ASCII decimal digit. Present ONLY for Mode 0 and Mode 1. Absent for Mode 2.
          '0' = Input Transaction Data is not pre-padded (HSM applies CUP Appendix D.2 padding)
          '1' = Input Transaction Data is already padded
          CUP padding rule: if data is multiple of 8 bytes, append 0x8000000000000000;
          if not multiple of 8, append 0x80 then 0x00 bytes to reach next 8-byte boundary.
          For APC: consume and discard; APC handles padding internally.
          FIELD IS MISSING from the incorrect proxy stub.
      - name: "Transaction Data Length [Modes 0,1 only]"
        type: 2H
        details: >
          Present ONLY for Mode 0 and Mode 1. Absent for Mode 2.
          2 ASCII hex chars encoding the byte count of Transaction Data. Range "01"-"FF" (1-255 bytes).
          WRONG assumption in proxy stub: stub reads 4H (TXN_LEN_FIELD=4) and treats data as ASCII hex.
          Correct: read 2 ASCII hex chars, parse as hex byte count, then read that many binary bytes.
      - name: "Transaction Data [Modes 0,1 only]"
        type: nB
        details: >
          Present ONLY for Mode 0 and Mode 1. Absent for Mode 2.
          Variable-length raw binary bytes. Byte count = Transaction Data Length field value.
          EMV terminal transaction data (CDOL1-related dataset used to generate the ARQC).
          WRONG assumption in proxy stub: stub reads txn_byte_len * 2 bytes (treating as ASCII hex).
          Correct: read txn_byte_len raw binary bytes, then hex-encode for APC.
      - name: "Delimiter [Modes 0,1 only]"
        type: 1A
        details: >
          Present ONLY for Mode 0 and Mode 1. Absent for Mode 2.
          ASCII ';' = 0x3B. Field separator after Transaction Data.
          Same as KQ — validate and consume.
          MISSING from the incorrect proxy stub.
      - name: "ARQC/TC/AAC"
        type: 8B
        details: >
          8 raw binary bytes. Present for ALL modes (0, 1, 2).
          Mode 0/1: the ARQC (Authorization Request Cryptogram) to verify.
          Mode 2: the TC/AAC previously verified — used as input for ARPC derivation without re-verification.
          WRONG assumption in proxy stub: reads as 16H ASCII (ARQC_LEN=16). Correct: 8 binary bytes.
      - name: "ARC [Modes 1,2 only]"
        type: 2B
        details: >
          2 raw binary bytes. Authorization Response Code for ARPC generation.
          NOT present for Mode 0. MUST be present for Mode 1 and Mode 2.
          ARPC Method 1 (XOR-based): ARPC = AES/3DES(ICC session key, ARQC XOR ARC||padding).
          No ARPC Method 2 (CSU) support — JS command has no CSU field.
          WRONG assumption in proxy stub: reads as 4H ASCII (ARC_LEN=4). Correct: 2 binary bytes.
      - name: "Delimiter [Optional]"
        type: 1A
        details: "ASCII '%'. Optional. If present, LMK Identifier field follows."
      - name: "LMK Identifier [Optional]"
        type: 2N
        details: "2 ASCII decimal digits. Min '00'. Present only if '%' delimiter present. Proxy: consume and ignore (proxy uses key_map for ARN resolution)."
      - name: "End Message Delimiter [Optional]"
        type: 1C
        details: "Value X'19'. Present only if Message Trailer is present."
      - name: "Message Trailer [Optional]"
        type: nA
        details: "Up to 32 ASCII chars."

  wire_format_response:
    response_code: JT
    fields:
      - name: Message Header
        type: mA
        details: Returned to host unchanged.
      - name: Response Code
        type: 2A
        details: Value 'JT'.
      - name: Error Code
        type: 2N
        details: >
          00 = No error
          01 = ARQC/TC/AAC verification failed (diagnostic ARQC returned in Diagnostic Data field if HSM in Authorised State)
          03 = Invalid Padding Flag
          04 = Mode Flag not 0, 1 or 2
          05 = Unrecognized Scheme ID
          10 = MK parity error
          67 = Command not licensed (PS10-LIC-LEGACY required)
          80 = Data length error
          81 = Zero length Transaction Data
          82 = Transaction Data length not multiple of 8 bytes
      - name: "ARPC [Modes 1,2 only, if no error]"
        type: 8B
        details: "The calculated ARPC. Present only for Modes 1 and 2 if error code is 00."
      - name: "Diagnostic Data [error 01 only]"
        type: 8B
        details: "Calculated ARQC/TC/AAC. Returned only if error code is 01 and HSM is in Authorised State."

  key_differences_from_kq:
    summary: "JS (Legacy, UnionPay) vs KQ (Core International, Visa/MC/Amex) — proxy authors must read both specs"
    differences:
      no_key_type_field: "KQ has a 3H Key Type field (e.g., '00E') before the key. JS does NOT. Parsing JS like KQ skips 3 chars of actual key material."
      key_base_length: "KQ key uses parse_legacy_key (base 16H = single-length). JS key uses parse_key_32 (base 32H = always double-length minimum)."
      scheme_id_meaning: "KQ SchemeID '0'=Visa/Amex (EmvOptionA), '1'=MC (EmvOptionB). JS SchemeID always '1'=CUP (not MC!)."
      padding_flag: "KQ has no Padding Flag field. JS has an explicit Padding Flag (1N) for Modes 0/1."
      txn_length_type: "KQ TxnLen is 2B binary big-endian. JS TxnLen is 2H ASCII hex (2 chars, max 'FF'=255)."
      txn_data_type: "Both are nB binary. KQ: read n binary bytes. JS: read n binary bytes (same, but proxy stub incorrectly treats as ASCII hex)."
      mode_values: "KQ modes: 0=verify, 1=Method1(ARC), 2=Method2(CSU), 3/4=skip-verify. JS modes: 0=verify, 1=verify+ARPC, 2=ARPC-only. JS has no CSU (Method 2) field and no modes 3/4."
      session_key_derivation: "KQ: SessionKeyDerivation::EmvCommon (Visa/MC). JS: SessionKeyDerivation::Emv2000 (CUP/PBOC)."
      major_key_deriv_mode: "KQ: EmvOptionA (scheme='0') or EmvOptionB (scheme='1'). JS: always EmvOptionA (CUP uses Option A-style IMK diversification)."

  known_proxy_bugs:
    file: "src/handlers/thales/unionpay_arqc.rs"
    bugs:
      - "Mode '9' in match arm — does not exist per PUGD0538; Mode '2' (ArpcOnly) rejected as unknown but is valid"
      - "KEY_TYPE_LEN=3 skip before key — JS has no key type field; this consumes 3 chars of actual key"
      - "parse_legacy_key used (base 16H) — should be parse_key_32 (base 32H)"
      - "Scheme ID field not parsed — byte after Mode Flag is Scheme ID but is silently consumed as part of key type"
      - "PAN read as PAN_LEN=16 ASCII bytes — should be 8 binary bytes decoded via decode_bcd_pan_seq"
      - "ATC read as 4H ASCII — should be 2 binary bytes hex-encoded"
      - "Padding Flag field completely absent — must consume 1N between ATC and TxnLen for Modes 0/1"
      - "TXN_LEN_FIELD=4 (4 hex chars) — should be 2 (2 hex chars, max FF=255)"
      - "TxnData read as ASCII hex (txn_byte_len * 2 chars) — should be txn_byte_len binary bytes"
      - "No 0x3B delimiter check before ARQC — required for Modes 0/1"
      - "ARQC read as 16H ASCII (ARQC_LEN=16) — should be 8 binary bytes"
      - "ARC read as 4H ASCII (ARC_LEN=4) — should be 2 binary bytes"
      - "[PUGD0538?] markers now resolved — remove all"

  apc_mapping:
    operation: verify_auth_request_cryptogram
    key_type: TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS
    session_key_derivation: SessionKeyDerivation::Emv2000
    major_key_derivation_mode: MajorKeyDerivationMode::EmvOptionA
    arpc_method: ArpcMethod1 (CryptogramVerificationArpcMethod1 with auth_response_code from ARC field)
    arpc_method2_csu: "Not supported by JS command — no CSU field in wire format"
    mode2_limitation: >
      APC's verify_auth_request_cryptogram always verifies the cryptogram and requires TransactionData.
      JS Mode 2 omits TransactionData from the wire. Mode 2 cannot be directly translated to APC.
      Recommendation: reject Mode 2 with a clear error; instruct applications to use Mode 1 (verify+generate).

  padding_rule:
    source: "CUP doc JR/T 0025.5-2010, Appendix D.2"
    rule: >
      If Transaction Data length is a multiple of 8 bytes: append 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 (8 bytes).
      If not a multiple of 8 bytes: append 0x80 then 0x00 bytes until the next multiple of 8.
      Padding Flag '1' means host already applied this; '0' means HSM applies it.
      APC applies its own padding internally; consume Padding Flag without forwarding.

constraints:
  - "JS requires PS10-LIC-LEGACY license; if not licensed, HSM returns error 67"
  - "Scheme ID '1' is the only valid value; other values return error 05"
  - "Mode Flag '4' returns error 04 — same wording as PUGD0538 error code 04"
  - "Zero-length Transaction Data returns error 81"
  - "Transaction Data not a multiple of 8 bytes returns error 82 (if Padding Flag='0')"
  - "ARC is NOT optional for Mode 1 or Mode 2 — omission causes a parse failure"

relationships:
  - type: related_to
    target_id: concept.thales-key-type-mapping
  - type: related_to
    target_id: concept.thales-wire-protocol
  - type: related_to
    target_id: operation.emv-arqc-generation
status: active
```

---

## Reference Catalogs to Materialize Next

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
| 2026-05-14 | Wikipedia enrichment: DUKPT, ISO 9564, EMV, ISO 8583, contactless, ATR, ISO/IEC 7816 | Wikimedia Foundation | live pages accessed 2026-05-14 | pin_processing, key_management, emv, iso8583, cryptography |
| 2026-05-14 | General Payment HSM Integration Guide | Futurex | public PDF, 34 pages, accessed 2026-05-14 | hsm, key_management, cryptography, pin_processing, emv |
| 2026-05-14 | payShield 10K Legacy Host Commands | Thales | Version V1, 2019 | hsm, key_management, cryptography |
| 2026-05-14 | payShield 10K Installation and User Guide | Thales | updated 15 January 2021 | hsm, key_management, cryptography |
| 2026-05-15 | Security Rules and Procedures, Merchant Edition | Mastercard | 11 February 2025 | card_data, card_validation, emv |
| 2026-05-15 | Visa Core Rules and Visa Product and Service Rules | Visa | 18 April 2026 public edition | emv, card_data, card_validation, cryptography |
| 2026-05-19 | AWS Payment Cryptography User Guide (full site tree: what-is, concepts, terminology, cryptographic-details, keys-import/export, valid-attributes, use-cases issuers/acquirers, security, physical key exchange, BYOCA, dynamic keys, post-quantum TLS) | AWS | accessed 2026-05-19 | key_management, pin_processing, card_validation, emv, cryptography, hsm |
| 2026-05-19 | Direct APC API testing: 11 symmetric keys imported via KEY_CRYPTOGRAM (RSA-3072 OAEP), 20 operations cross-validated between CyberChef Payments and APC data plane. Findings: mac_length nibbles, ISO9797 Method 1, DUKPT data variant, ARQC AES-256 requirement, D0/E0/P0 NoRestrictions, re-encrypt block, KEY_CRYPTOGRAM import quirks, IBM 3624 pad char | Direct API testing (CyberChef Payments vs AWS Payment Cryptography) | live 2026-05-19 | cryptography, pin_processing, key_management, emv |
| 2026-05-19 | PCI PTS PIN Security Requirements Technical FAQs v3 | PCI Security Standards Council | June 2021 | compliance, key_management, pin_processing, hsm |
| 2026-05-19 | PCI PIN Security Requirements Modifications Summary of Changes v2.0 to v3.0 | PCI Security Standards Council | August 2018 | compliance, pin_processing, cryptography |
| 2026-05-19 | PCI Information Supplement: Implementing ISO Format 4 PIN Blocks | PCI Security Standards Council | September 2021 (v1.01) | compliance, pin_processing, cryptography |
| 2026-05-19 | PCI Information Supplement: PIN Security Requirement 18-3 – Key Blocks | PCI Security Standards Council | June 2019 | compliance, key_management |
| 2026-05-19 | Use of triple length TDES in ep2 v7.x with regard to PCI SSC requirements (expert opinion letter) | SRC Security Research & Consulting GmbH / Technical Cooperation ep2 | October 30, 2020 | compliance, cryptography, pin_processing |
| 2026-05-21 | PCI Point-to-Point Encryption (P2PE) Standard v3.2 — Domains 1–5, Appendix A, Normative Annex C (full standard read; pages 1-251) | PCI Security Standards Council | v3.2, June 2025 | compliance, key_management, cryptography, pin_processing, hsm |
| 2026-05-21 / 2026-05-25 | PCI PIN Security Requirements and Testing Procedures v3.1 (normative standard — all 7 Control Objectives, Req 1-33, Annex A TR-34, Annex B KIF/secure-room, Annex C key equivalence, Glossary). Second pass 2026-05-25: added Dual Control/Split Knowledge (Req 6-1.2/21-2), Email Prohibition (Req 8-3), Component Channel Separation (Req 8-1 Note), and confirmed Annex C minimum key size table (DEA 112-bit, RSA 2048, ECC 224, AES 128). | PCI Security Standards Council | v3.1 March 2021 | compliance, key_management, pin_processing, hsm, cryptography |
| 2026-05-21 | PCI Mobile Payments on COTS (MPoC) Standard v1.1 (targeted read: overview/scope pp.15-35, Req 1A-3 crypto pp.56-58, Req 1A-4 key mgmt pp.60-68, Req 4A-2 back-end ops pp.168-170, Req 4A-4 compliance stack p.180, Appendix C pp.237-239) | PCI Security Standards Council | v1.1, November 2024 | compliance, key_management, cryptography, pin_processing, hsm |
| 2026-05-21 | PCI Contactless Payments on COTS (CPoC) Standard v1.0 (full targeted read: overview pp.5-20, Section 1.3 crypto pp.32-36, Section 1.4 key mgmt pp.36-42, Section 1.5 secure channels pp.43-44, Section 2.9 account data encryption pp.86-87, Module 3 attestation pp.88-109, Module 4 back-end processing p.117, Module 5 contactless kernel pp.118-121, Appendix C pp.146-148) | PCI Security Standards Council | v1.0, December 2019 | compliance, key_management, cryptography, hsm, emv |
| 2026-05-22 | PCI 3DS Core Security Standard v1.0 (targeted read: pp.1-20 overview/Part 1 baseline; pp.45-58 P2-5 Protect 3DS data, P2-6 Cryptography and Key Management, P2-7 Physical security; pp.59-65 appendices) | PCI Security Standards Council | v1.0, October 2017 | compliance, key_management, cryptography, hsm, 3ds |
| 2026-05-22 | EMV Integrated Circuit Card Specifications for Payment Systems, Book 2 — Security and Key Management (targeted read: ToC; Section 5 SDA certificate chain; Section 8 ARQC/ARPC — Table 26 minimum dataset, Method 1 and Method 2 ARPC; Section 9 Secure Messaging — MAC/encipherment session keys, MAC chaining, Format 1/2; Annex A1.3 session key derivation, A1.4 ICC master key derivation Options A/B/C; Annex B approved algorithms) | EMVCo | v4.3, November 2011 | emv, cryptography, key_management |
| 2026-05-22 | EMV Book 2 — Security and Key Management v4.4 delta read (targeted: cover/revision log/ToC pp.1-10; Annex B Approved Algorithms pp.151-169 — Table 43 RSA modulus corrections per Bulletin 208, B2 ECC P-256/P-521 curve parameters, Table 47 hash algorithm indicators, Table 48 ECC signature suites, Table 49 ODE encryption suites; Bulletin 162 AES key derivation erratum noted) | EMVCo | v4.4, November 2023 | emv, cryptography, key_management |
| 2026-05-22 | EMV Integrated Circuit Card Specifications for Payment Systems, Book 3 — Application Specification, Annex A full read (A1 Data Elements by Name pp.135-161, A2 Data Elements by Tag pp.162-167); replaces prior kabc.ca-sourced tag catalog with authoritative definitions including tag 91 length correction, exponent corrections, missing tags (42, 4F, 73, 81, 83, 86-89, 9F0A, 9F0C, 9F19, 9F25), and new biometric tags from v4.4 (7F60, A1, 9F30, 9F31, BF4A-BF4E, DF50-DF54) | EMVCo | v4.4, October 2022 | emv, cryptography, key_management |
| 2026-05-25 | payShield 10K Host Programmer's Manual (targeted read: Ch.3 TCP/IP wire protocol; Ch.4 RTKS and Australian AS2805 TKS command disambiguation; Ch.5 RSA command set; pages 97-116 Key Block and Variant Comparison Table, Variant key type code full list pp.113-114, BDK type taxonomy, AES DUKPT; DUKPT KSN descriptor encoding). Records added: KSN descriptor, key type cross-reference table, BDK-1 through BDK-5 taxonomy, LMK migration guide, AES DUKPT migration, wire protocol framing, RTKS/AS2805 command disambiguation. | Thales | PUGD0541-003, Revision A, 04 August 2020 | hsm, key_management, pin_processing, cryptography |
| 2026-05-25 | payShield 10K Legacy Host Commands §7 pp.121-126 (full read: Legacy UnionPay Commands section — JS command wire format pp.122-123, JU command wire format pp.124-126). JS record added: complete field-by-field wire format, 7 confirmed proxy bugs with field-level detail, key differences vs KQ, APC mapping, Mode 2 limitation, CUP padding rule. | Thales | PUGD0538-003, Revision A, 04 August 2020 | hsm, emv, cryptography, key_management |
| 2026-05-22 | EMV Tag Catalog — kabc.ca/emv/tags | https://www.kabc.ca/emv/tags (public reference) | n/a | emv, tlv, tags |
