//import Security from '@ki1r0y/distributed-security';


export const Collection = superclass => class extends superclass {
  // Security = TeamSecurity;
  // Identity = Immutable;
  constructor({name, Security, Identity, Storage, ...rest}) {
    super(rest);
    this.name = name;
    if (Security) this.Security = Security;
    if (Identity) this.Identity = Identity;
    if (Storage) this.Storage = Storage;
  }

  async store(persistable, initialOptions = {time: Date.now()}) { // Promise the tag by which persistable has been stored.
    // Note: Even though store is asynchronous, a SHALLOW copy is immediately captured.
    const options = this.storeOptions(persistable, initialOptions),
          identity = await this.identify(persistable, options),
          [signed, tag] = await this.Identity.package(this.Security, identity, options);
    await this.Storage.store(this.name, tag, signed);
    return tag;
  }
  storeOptions(persistable, options) { // Copy the big four non-identity properties into options: author, audience antecedent, and owner.
    const {owner, author = owner, audience, antecedent} = persistable;
    return {owner, author, audience, antecedent, ...options};
  }
  identify(persistable, options) { // Make a copy of the properties of persistable, in which the property names are sorted and do not contain any names from options.
    const propertyNames = Object.keys(persistable).sort(),
          specification = {};
    propertyNames.forEach(key => (key in options) || (specification[key] = persistable[key]));
    return specification;
  }

  async retrieve(tag, initialOptions = {}) { // Promise a ready-to-use bag of properties retrieved from storage by tag.
    const options = this.retrieveOptions(tag, initialOptions),
          packaged = await this.Storage.retrieve(this.name, tag),
          unpackaged = await this.Identity.unpackage(this.Security, packaged, options);
    return unpackaged;
  }
  retrieveOptions(tag, options) {
    return options;
  }
};

