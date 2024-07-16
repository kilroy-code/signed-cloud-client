import Security from '@ki1r0y/distributed-security';

export const TeamSecurity = {
  package(identity, options) {
    const {owner, author, time} = options, // fixme antecedent, 
          headers = (owner === author) ? {tags: [owner], iss: owner, iat: time} : {team: owner, member: author, time};
    return Security.sign(identity, headers);
  },
  async unpackage(packaged, options) {
    const verified = await Security.verify(packaged, options),
          {iss, act, iat} = verified.protectedHeader;
    return {...verified.json, ...(act ? {author: act} : {}), owner: iss, timestamp: iat};
  }
};

export const Immutable = {
  async package(security, identity, options) {
    const signed = await security.package(identity, options),
          claims = Security.decodeClaims(signed);
    return [signed, claims.sub];
  },
  unpackage(security, packaged, options) {
    return security.unpackage(packaged, options);
  }
};

export const Collection = superclass => class extends superclass {
  Security = TeamSecurity;
  Identity = Immutable;
  constructor({name, Security, Identity, Storage, ...rest}) {
    super(rest);
    this.name = name;
    if (Security) this.Security = Security;
    if (Identity) this.Identity = Identity;
    if (Storage) this.Storage = Storage;
  }

  async store(persistable, initialOptions = {time: Date.now()}) {
    const options = this.storeOptions(persistable, initialOptions),
          identity = await this.identify(persistable, options),
          [signed, tag] = await this.Identity.package(this.Security, identity, options);
    await this.Storage.store(this.name, tag, signed);
    return tag;
  }
  storeOptions(persistable, options) {
    const {owner, author = owner, audience, antecedent} = persistable;
    return {owner, author, audience, antecedent, ...options};
  }
  identify(persistable, options) {
    const propertyNames = Object.keys(persistable).sort(),
          specification = {};
    propertyNames.forEach(key => (key in options) || (specification[key] = persistable[key]));
    return specification;
  }

  async retrieve(tag, initialOptions = {}) {
    const options = this.retrieveOptions(tag, initialOptions),
          packaged = await this.Storage.retrieve(this.name, tag),
          unpackaged = await this.Identity.unpackage(this.Security, packaged, options);
    return unpackaged;
  }
  retrieveOptions(tag, options) {
    return options;
  }
};

