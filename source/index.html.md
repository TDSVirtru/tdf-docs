---
title: API Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - json--example
  - json--schema

toc_footers:
  - <a href='#'>Sign Up for a Developer Key</a>
  - <a href='https://github.com/lord/slate'>Documentation Powered by Slate</a>

includes:

search: true
---

# Notice

<aside class="warning">
These docs, and the schemas they define are very much a work in progress and are subject to change without notice.
</aside>

# Schemas

## manifest.json

### Summary

A TDF's manifest holds all the information a client would need to decrypt the file. It describes the location of the payload, the method used to encrypt it, information to verify its authenticity, the KASes a client must make requests to in order to get an unrapped key, etc. It also contains the TDF's policy which describes who, or what should be given access to the content.

```json--example
// Example
{
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true
  },
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "http:\/\/kas.gsk.com:5000",
        "protocol": "kas",
        "wrappedKey": "OqnOETpwyGE3PVpUpwwWZoJTNW24UMhnXIif0mSnqLVCUPKAAhrjeue11uAXWpb9sD7ZDsmrc9ylmnSKP9vWel8ST68tv6PeVO+CPYUND7cqG2NhUHCLv5Ouys3Klurykvy8\/O3cCLDYl6RDISosxFKqnd7LYD7VnxsYqUns4AW5\/odXJrwIhNO3szZV0JgoBXs+U9bul4tSGNxmYuPOj0RE0HEX5yF5lWlt2vHNCqPlmSBV6+jePf7tOBBsqDq35GxCSHhFZhqCgA3MvnBLmKzVPArtJ1lqg3WUdnWV+o6BUzhDpOIyXzeKn4cK2mCxOXGMP2ck2C1a0sECyB82uw==",
        "policyBinding": "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs=",
        "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU="
      }
    ],
    "method": {
      "algorithm": "aes-256-gcm",
      "isStreamable": false,
      "iv": "S5FtOSsesp3VfzfNHcHQpg=="
    },
    "integrityInformation":{
      "rootSignature": {
        "alg": "HS256",
        "sig": "eyJib2...V19fQ=="
      },
      "segmentSizeDefault": "1048576",
      "segmentHashAlg": "HS256",
      "segments": [
        {
          "segmentSize": "1048576",
          "hash": "eyJape...dq82UR9=="
        }
      ]
    },
    "policy": "eyJib2R5IjogeyJkYXRhQXR0cmlidXRlcyI6IFt7InVybCI6ICJodHRwczovL2V4YW1wbGUuY29tL2F0dHIvQ2xhc3NpZmljYXRpb24uUyIsICJuYW1lIjogIlRvcCBTZWNyZXQifSwgeyJ1cmwiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRyL0NPSS5QUlgiLCAibmFtZSI6ICJQcm9qZWN0IFgifV19fQ=="
  }
}
```

```json--schema
// Full JSON-Schema
{
  "$id": "https://virtru.com/schemas/tdf.json",
  "$schema": "https://json-schema.org/draft-07/schema#",
  "title": "TDF Manifest",
  "description": "A manifest file containing data about the TDF.",
  "type": "object",
  "required": [
    "payload",
    "encryptionInformation"
  ],
  "properties": {
    "payload": {
      "$ref": "#/definitions/payload"
    },
    "encryptionInformation": {
      "$ref": "#/definitions/encryptionInformation"
    }
  },
  "maxProperties": 2,
  "definitions": {
    "payload": {
      "description": "Contains metadata for the TDF's payload",
      "type": "object",
      "properties": {
        "type": {
          "description": "Type of payload",
          "type": "string",
          "examples": [
            "reference"
          ]
        },
        "url": {
          "description": "URL pointing to the location of the payload.",
          "type": "string"
        },
        "protocol": {
          "description": "Protocol used for packaging the TDF.",
          "type": "string",
          "examples": [
            "zip"
          ]
        },
        "isEncrypted": {
          "description": "Boolean designating whether or not the payload is encrypted",
          "type": "boolean"
        }
      }
    },
    "encryptionInformation": {
      "description": "Top level element for holding information related to the encryption of an assertion or payload. Also contains information about how to derive a key. ",
      "type": "object",
      "properties": {
        "type": {
          "type": "string",
          "description": "Information describing the encryption scheme.",
          "enum": [
            "split",
            "shamir"
          ]
        },
        "keyAccess": {
          "description": "Contains information describing the method of encryption. As well as information about one or more KASes which own the TDF.",
          "type": "array",
          "items":{
            "$ref": "https://virtru.com/schemas/key-access-object.json"
          }
        },
        "method": {
          "description": "Object describing the encryption method",
          "type": "object",
          "properties": {
            "isStreamable": {
              "type": "boolean",
              "description": "The type of method used for encryption. Chunked vs. a single chunk payload"
            },
            "algorithm": {
              "description": "The encryption algorithm used to encrypt the payload",
              "type": "string",
              "examples": [
                "aes-256-gcm"
              ]
            },
            "iv": {
              "description": "Base64 initialization vector",
              "type": "string"
            }
          },
          "required": [
            "algorithm",
            "iv"
          ]
        },
        "integrityInformation": {
          "type": "object",
          "description": "An object which allows an application to validate the integrity of the payload. Or a chunk of a payload should it be a streamable TDF.",
          "properties": {
            "rootSignature": {
              "type": "object",
              "description": "Object containing a signature for the entire payload, and the algorithm used to generate it.",
              "properties": {
                "alg": {
                  "type": "string",
                  "description": "The algorithm used to generate the root signature",
                  "examples": [
                    "HS256"
                  ]
                },
                "sig": {
                  "type": "string",
                  "description": "The signature for the entire payload. Base64.encode(HMAC(payload, payloadKey))"
                }
              }
            },
            "segmentSizeDefault": {
              "type": "string",
              "description": "The default size of each chunk, or segment in bytes. By setting the default size here, the segments array becomes more space efficient as it will not have to specify the segment size each time."
            },
            "segmentHashAlg": {
              "type": "string",
              "description": "The hashing algorithm used to generate the hashes for each segment."
            },
            "segments": {
              "type": "array",
              "description": "An array of objects containing each segment hash info.",
              "items": {
                "type": "object",
                "description": "Object containing integrity information about a segment of the payload.",
                "properties": {
                  "hash": {
                    "type": "string",
                    "description": "A hash generated using the specified 'segmentHashAlg'. hash = Base64.encode(HMAC(segment, payloadKey))"
                  },
                  "segmentSize": {
                    "type": "string",
                    "description": "The size of the segment. This field is optional. The size of the segment is inferred from 'segmentSizeDefault' defined above, but in the event that a segment were modified and re-encrypted, the segment size would change."
                  }
                }
              }
            }
          }
        },
        "policy": {
          "description": "A base64 encoded version of the policy object. The policy object is defined here:: https://virtru.com/schemas/tdf-policy-object.json",
          "type": "string"
        }
      }
    }
  }
}
```

### payload

| Parameter           | Type    | Description                                                                                                                                   |
| ------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| payload             | Object  | Contains metadata for the TDF's payload. Including type, url, protocol and isEncrypted.                                                       |
| payload.type        | String  | Type of payload. The type would describe where to get the payload. Is it contained within the TDF, for example, or stored on a remote server. |
| payload.url         | String  | A url pointing to the location of the payload                                                                                                 |
| payload.protocol    | String  | Designates which protocol was used. Currently, only ZIP is supported.                                                                         |
| payload.isEncrypted | Boolean | Designates whether or not the payload is encrypted                                                                                            |

### encryptionInformation

| Parameter                                 | Type    | Description                                                                                                                                                                                                              |
| ----------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| encryptionInformation                     | Object  | Contains information describing the method of encryption. As well as information about one or more KASes which own the TDF.                                                                                              |
| encryptionInformation.type                | String  | The type of scheme used for accessing keys, and providing authorization to the payload. The schema supports multiple options, but currently the only option supported by our libraries is `split`.                       |
| encryptionInformation.keyAccess           | Array   | An array of keyAccess Objects. Defined in the next section below.                                                                                                                                                        |
| encryptionInformation.method              | Object  | An object which describes the information required to actually decrypt the payload once the key is retrieved. Includes the algorithm, and iv at a minimum.                                                               |
| encryptionInformation.method.algorithm    | String  | The algorithm used for encryption. ie. `aes-256-gcm`                                                                                                                                                                     |
| encryptionInformation.method.isStreamable | boolean | isStreamable designates whether or not a TDF payload is streamable. If it's streamable, the payload is broken into chunks, and indivdual hashes are generated per chunk to establish integrity of the individual chunks. |
| encryptionInformation.method.iv           | String  | The initialization vector for the encrypted payload.                                                                                                                                                                     |

### keyAccessObject

The keyAccessObject is defined in its own section [below](#keyaccessobject-2).

### integrityInformation

| Parameter                                         | Type   | Description                                                                                                                                                                                                                  |
| ------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| integrityInformation                              | Object | An object which allows an application to validate the integrity of the payload. Or a chunk of a payload should it be a streamable TDF.                                                                                       |
| integrityInformation.rootSignature                | Object | Object containing a signature for the entire payload, and the algorithm used to generate it.                                                                                                                                 |
| integrityInformation.rootSignature.alg            | String | The algorithm used to generate the root signature                                                                                                                                                                            |
| integrityInformation.rootSignature.sig            | String | The signature for the entire payload. <br><br> `Base64.encode(HMAC(payload, payloadKey))`                                                                                                                                    |
| integrityInformation.segmentSizeDefault           | String | The default size of each chunk, or segment in bytes. By setting the default size here, the segments array becomes more space efficient as it will not have to specify the segment size each time.                            |
| integrityInformation.segmentHashAlg               | String | The hashing algorithm used to generate the hashes for each segment.                                                                                                                                                          |
| integrityInformation.segments                     | Array  | An array of objects containing each segment hash info.                                                                                                                                                                       |
| integrityInformation.segments item                | Object | Object containing integrity information about a segment of the payload.                                                                                                                                                      |
| integrityInformation.segments segment.hash        | String | A hash generated using the specified 'segmentHashAlg'. `Base64.encode(HMAC(segment, payloadKey))`                                                                                                                            |
| integrityInformation.segments segment.segmentSize | String | The size of the segment. This field is optional. The size of the segment is inferred from 'segmentSizeDefault' defined above, but in the event that a segment were modified and re-encrypted, the segment size would change. |

### policy

| Parameter | Type   | Description                                                                                                                 |
| --------- | ------ | --------------------------------------------------------------------------------------------------------------------------- |
| policy    | String | The policy object which has been JSON stringified, then base64 encoded. The policy object is described in the next section. |

## keyAccessObject

### Summary

A summary of the key access object

```json--example
  {
    "type": "wrapped",
    "url": "http:\/\/kas.gsk.com:5000",
    "protocol": "kas",
    "wrappedKey": "OqnOETpwyGE3PVpUpwwWZoJTNW24UMhnXIif0mSnqLVCUPKAAhrjeue11uAXWpb9sD7ZDsmrc9ylmnSKP9vWel8ST68tv6PeVO+CPYUND7cqG2NhUHCLv5Ouys3Klurykvy8\/O3cCLDYl6RDISosxFKqnd7LYD7VnxsYqUns4AW5\/odXJrwIhNO3szZV0JgoBXs+U9bul4tSGNxmYuPOj0RE0HEX5yF5lWlt2vHNCqPlmSBV6+jePf7tOBBsqDq35GxCSHhFZhqCgA3MvnBLmKzVPArtJ1lqg3WUdnWV+o6BUzhDpOIyXzeKn4cK2mCxOXGMP2ck2C1a0sECyB82uw==",
    "policyBinding": {
      "alg": "HS256",
      "hash": "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs="
    },
    "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU="
  }
```

```json--schema
{
  "$id": "https://virtru.com/schemas/key-access-object.json",
  "$schema": "https://json-schema.org/draft-07/schema#",
  "title": "Key access object",
  "description": "KeyAccess object stores all information about how an object key OR key split is stored, and if / how it has been encrypted (eg with KEK or pub wrapping key)",
  "type": "object",
  "required": [
    "type",
    "url",
    "protocol",
    "wrappedKey",
    "policyBinding",
    "metadataKek",
    "encryptedMetadata"
  ],
  "properties": {
    "type": {
      "type": "string",
      "description": "Specifies how the key is stored.",
      "examples": [
        "remote",
        "remoteWrapped",
        "wrapped"
      ]
    },
    "url": {
      "type": "string",
      "description": "URL pointing to the KAS",
      "examples": [
        "https:\/\/kas.gsk.com:5000"
      ]
    },
    "protocol": {
      "type": "string",
      "description": "Protocol being used for this split.",
      "examples": [
        "kas"
      ]
    },
    "wrappedKey": {
      "type": "string",
      "description": "The base64 wrapped key used to encrypt the payload"
    },
    "policyBinding": {
      "type": "object",
      "description": "Base64 Signature of the policy. Signed using the public key of the KAS.",
      "properties": {
        "alg": {
          "description": "The algorithm used to generate the hash"
        },
        "hash": {
          "description": "Base64 string of the generated hash"
        }
      }
    },
    "encryptedMetadata": {
      "type": "string",
      "description": "Metadata for the policy which has been encrypted, then base64 encoded",
      "examples": [
        "R5IjogeyJkY=="
      ]
    }
  }
}
```

| Parameter          | Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keyAccessObject    | Object | KeyAccess object stores all information about how an object key OR key split is stored, and if / how it has been encrypted (eg with KEK or pub wrapping key)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| type               | String | Specifies how the key is stored. <br> <br> Possible Values: <br> `remote`: Stored and fetched like a KMS or ACM SAAS) <br>`remoteWrapped` Like our CKS / ACM today <br> `wrapped` Wrapped and embedded key. Default for TDF3.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| url                | String | A url pointing to the KAS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| protocol           | String | Protocol being used. Currently only KAS is supported                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| wrappedKey         | String | The symetric key used to encrypt the payload. It has been encrypted using the public key of the KAS, then base64 encoded.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| policyBinding      | Object | Object describing the policyBinding. Contains a hash, and an alg.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| policyBinding.alg  | String | The policy binding algorithm used to generate the hash                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| policyBinding.hash | String | This contains a KEYED HASH that will provide cryptographic integrity on the policy object, such that it cannot be modified or copied to another TDF, without invalidating the binding. Specifically, you would have to have access to the key in order to overwrite the policy. <br><br> This is Base64 encoding of HMAC(POLICY,KEY), where: <br><br> **POLICY**: base64(policyjson) that is in the “encryptionInformation/policy” <br> **HMAC**: HMAC SHA256 (default, but can be specified in the alg field described above) <br> **KEY**: Whichever Key Split or Key that is available to the KAS (e.g. the underlying AES 256 key in the wrappedKey. |
| encryptedMetadata  | String | Metadata associated with the TDF, and the request. The contents of the metadata are freeform, and are used to pass information from the client, and any plugins that may be in use by the KAS. For example, in Virtru's scenario, we could include information about things like, watermarking, expiration, and also data about the request. Things like clientString, could also be placed here.                                                                                                                                                                                                                                                        |

## Policy Object

### Summary

The policy object is an object generated by the client at the time of the payload's encryption. It contains information required for the KAS to make an access decision, such as, `dataAttributes`, and `dissem`. The policyObject is stored in the manifest.json for a TDF, and sent to the KAS along with an entity object so that the KAS may make an access decision.

By default, a KAS instance is stateless, but by using plugins may sync the policy data received from an access request using a datastore of its choice. It's up to the developer of a plugin to determine how that data is stored in their store, but it's recommended they choose something like outlined in the schema so as to simply the adapter logic in the plugin.

```json--schema
{
  "$id": "https://virtru.com/schemas/policy.json",
  "$schema": "https://json-schema.org/draft-07/schema#",
  "title": "TDF Policy object",
  "description": "Policy for the TDF. Includes attributes, and encrypted metadata for the KAS",
  "type": "object",
  "required":[
    "uuid",
    "body"
  ],
  "properties": {
    "uuid": {
      "type": "string",
      "description": "A UUID for the policy, generated by the client which created the TDF",
      "examples": [
        "630086f5-f238-4cd1-897c-0a7bd4da6f66"
      ]
    },
    "body": {
      "type": "object",
      "description": "TODDO: Fill this in",
      "properties": {
        "dataAttributes": {
          "type": "array",
          "description": "Attributes associated with the policy. Used by KAS to make access decisions",
          "items": {
            "type": "object",
            "description": "An attribute object",
            "properties": {
              "url": {
                "type": "string",
                "description": "A url pointing to an attribute's policy",
                "examples":[
                  "https:\/\/example.com\/attr\/Classification.TS"
                ]
              },
              "name": {
                "type": "string",
                "description": "The name of the attribute",
                "examples":[
                  "Top Secret"
                ]
              }
            }
          }
        }
      },
      "required": [
        "dataAttributes"
      ]
    },
    "dissem": {
      "type": "array",
      "description": "An array of userIds to be given access to the TDF content",
      "items": {
        "type": "string",
        "description": "A userID, most likely an email",
        "examples": [
          "johndoe@virtru.com"
        ]
      }
    }
  }
}
```

```json--example
{
"uuid": "1111-2222-33333-44444-abddef-timestamp",
"body": {
    "dataAttributes": [
      {
        "url": "https:\/\/example.com\/attr\/Classification.S",
        "name": "Top Secret"
      },
      {
        "url": "https:\/\/example.com\/attr\/COI.PRX",
        "name": "Project X"
      }
    ],
    "dissem": [
      "user-id@domain.com"
    ]
  }
}
```

### uuid

| Parameter | Type   | Description                         |
| --------- | ------ | ----------------------------------- |
| uuid      | String | A unique UUID for the TDF's policy. |

### body

| Parameter           | Type   | Description                                                                                                         |
| ------------------- | ------ | ------------------------------------------------------------------------------------------------------------------- |
| body                | Object | Object which contains information about the policy required for the KAS to make an access decision.                 |
| body.dataAttributes | Array  | An array of dataAttributes. dataAttributes are defined in the next sub-section.                                     |
| body.dissem         | Array  | An array of unique userIds. It's used to explicitly list users/entities that should be given access to the payload. |

## Entity Object

### Summary

The entity object is an object generated by the AA to define an entity. It contains both the entity's public key, for certification purposes, and the attributes associated with the entity.

```json--schema
{
  "$id": "https://virtru.com/schemas/entity.json",
  "$schema": "https://json-schema.org/draft-07/schema#",
  "title": "TDF Entity object",
  "description": "Entity for the TDF. Includes attributes and entity private key.",
  "type": "object",
  "properties": {
    "entity_attributes": { "$ref": "#/definitions/entity_attributes" },
    "public_key": { "$ref": "#/definitions/public_key" }
  },
  "required": [
    "entity_attributes",
    "public_key"
  ],
  "maxProperties": 2,
  “definitions” :{
    "entity_attributes": {
      "type": "array",
      "title": "The EntityAttributes Schema ",
      "default": [],
      "items": { "$ref": "#/definitions/entity_attribute" }
    },
    "entity_attribute": {
      "type": "object",
      "title": "The EntityAttribute Schema ",
      "properties": {
        "url": { "$ref": "#/definitions/url" },
        "attributes": { "$ref": "#/definitions/attributes" }
      },
     	"required": ["url", "attributes"],
      "maxProperties": 2
    },
    "attribute": {
      "type": "string",
      "title": "The Attribute Schema ",
      "default": "",
      "examples": ["PRX", "AAA", "TS", "USA"]
    },
    "attributes": {
      "type": "array",
      "items": { "$ref": "#/definitions/attribute" }
    },
    "public_key": {
      "type": "string",
      "title": "The Public_key Schema ",
      "default": ""
    },
    "url": {
      "type": "string",
      "title": "The Url Schema ",
      "examples": [
        "https://example.com/attr/COI",
        "https://example.com/attr/Classification",
        "https://example.com/attr/Rel"
      ]
    }
  }
}
```

```json--example
{
  "entity_attributes": [
    {
      "url": "https://example.com/attr/COI",
      "attributes": ["PRX", "AAA"]
    },
    {
      "url": "https://example.com/attr/Classification",
      "attributes": ["TS"]
    },
    {
      "url": "https://example.com/attr/Rel",
      "attributes": ["USA"]
    }
  ],
  "public_key":
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzNH7sQbY8NyoghL0WWhK\n/YmY0yrYJDm3MCSlRVBKHpB1Zbjes2/SXGKhTCifTtHVF5YABPM+XBVTvpo3paEk\n3vsWYXizFfS5FKtHu3k0CExBMjkD7Wb3Uck2FTTRJlgyonwe6Wd6MzuqDqGWk7Iz\nhxnub6dx+UCCi5ZfXpPL6dFMd936Vu+VrKitYJ7sWVN1jOiMfsh2KvVlG5ycb98q\nwPsbi8U9yek8RtZ9KSsde4Uz+MQx1pFNNFmTJ3Wd4inrZcMqJ5NTaxXHGTAWt88b\nP1r30n93qH5EYlwCrgAkjZkEwF04n6kKDI7rus7VN9rx+SE2dTun+Yw1VwzZTY7P\nrQIDAQAB\n-----END PUBLIC KEY-----\n"
}
```

### entity_attributes

| Parameter         | Type  | Description                                          |
| ----------------- | ----- | ---------------------------------------------------- |
| entity_attributes | Array | A list of the attributes associated with the entity. |

### public_key

| Parameter  | Type   | Description                           |
| ---------- | ------ | ------------------------------------- |
| public_key | String | The entity's public key, PEM encoded. |
