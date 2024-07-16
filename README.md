# Signed-Cloud Client

Extensible utility for saving and retrieving things via a [Signed Cloud Server API](https://github.com/kilroy-code/signed-cloud-server).

- [Distributed-Security](https://github.com/kilroy-code/distributed-security) is used for end-to-end encrypt content for a specified audience, so that there are no read-permissions to define or enforce.
- [Distributed-Security](https://github.com/kilroy-code/distributed-security) is used for non-repudiably signing and dating content, which combines with Signed Cloud Server's attribution model so that there are no write-permissions to define or enforce.
- Any standard media file can be saved, combined with an extensible set of metadata that is not in the media file formats.
- The immediate state of the object is synchronously identified at the time of the request, even though any actual saving happens asynchronously.


# API

## Collection

A class that implements `store` and `retrieve`.

### methods

**retrieve(tag)** - Promises a new instance of `Persistable` corresponding to the `tag` within collection. The result is verified and decrypted as needed and possible.

**store(persistable)** - Causes the given Persistable to be saved, promising a `tag` string that can be used to retrieve a copy of the same object. The persisted data will be signed and encrypted appropriiately to the persistable's data.  No network traffic occurs if the persistable has not changed since it was last saved or retrieved.

**register(name = this.constructor.name)** - Registers the collection so that it will be answered by `Collection.instance(name)`.


### static methods

**instance(name)** - Answers the collection that was registered by `collection.register(name)`.

(An application may retrieve a Collection and register it, but instance(name) does not do so. The semantics of tag and store require that instance(name) synchronously returns a Collection, not a promise.)


## Persistable(baseClass)

Defines the following, each of which can be extended by subclassing. Persistable is defined as a mixin so that any baseClass can be used.

**FIXME**: define these as getters, properties, etc.

### collectionName

Answers the name of the Collection that the Persistable should be stored in and retrieved from. (The name is resolved to a Collection using `Collection.instance(name)`.)

### signatureMap

Answers an object enumerating the property names that should *not* be included in the payload when the Persistable is stored, and thus do not contribute to the stored content hash. The values in this map may be falsy or a non-empty string. If the latter, the value of the propery appears under the specified name string in the *header* of the signature.

The default signatureMap is {author: "member", owner, "team", time: "time", antecedent: "antecedent"}, where "member", "team", and "time" are defined by [Distributed-Security](https://github.com/kilroy-code/distributed-security/blob/main/docs/advanced.md#signatures-with-multiple-tags-and-other-signature-options). If the "antecedent" property is present in the persistable being stored, the value is expected to be the tag of a previously stored persistable that the present object was derived from. The tag and value will appear in the signature header.

### tag

Answers a promise for a string that identifies the Persistable within its collection. It calls `Collection.instance(this.collectionName).store(this)`.

aud, id/tag/sub - tag usually means authentication tag, and sub usually means a human that the jwt applies to

note that encrypt will have it's own headers, specifying kid, so we don't need aud?