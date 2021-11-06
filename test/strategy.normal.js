const jwt = require('jsonwebtoken');
const chai = require('chai');

const expect = chai.expect;
chai.use(require('chai-passport-strategy'));

const Strategy = require('../lib/strategy');

const subject = 'subject';

let user;
let info;

const secret = Math.random().toString(36).replace(/[^a-z]+/g, '');
const strategy = new Strategy(
  secret,
  {},
  (token, done) => done(null, { id: token.sub }, token)
);

describe('Passport HTTP JWT Bearer Strategy', () => {
  describe('handling a request with valid token in header', () => {
    before((done) => {
      chai.passport.use(strategy)
        .success((u, i) => {
          user = u;
          info = i;
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });

    it('should supply user', () => {
      expect(user).to.be.an.object;
      expect(user.id).to.equal(subject);
    });

    it('should supply info', () => {
      expect(info).to.be.an.object;
      expect(info).to.have.property('sub', subject);
    });
  });

  describe('handling a request with valid token in form-encoded body parameter', () => {
    before((done) => {
      chai.passport.use(strategy)
        .success((u, i) => {
          user = u;
          info = i;
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.body = { access_token: encoded };
            next();
          });
        })
        .authenticate();
    });

    it('should supply user', () => {
      expect(user).to.be.an.object;
      expect(user.id).to.equal(subject);
    });

    it('should supply info', () => {
      expect(info).to.be.an.object;
      expect(info).to.have.property('sub', subject);
    });
  });

  describe('handling a request with valid credential in URI query parameter', () => {
    before((done) => {
      chai.passport.use(strategy)
        .success((u, i) => {
          user = u;
          info = i;
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.query = { access_token: encoded };
            next();
          });
        })
        .authenticate();
    });

    it('should supply user', () => {
      expect(user).to.be.an.object;
      expect(user.id).to.equal(subject);
    });

    it('should supply info', () => {
      expect(info).to.be.an.object;
      expect(info).to.have.property('sub', subject);
    });
  });

  describe('handling a request with wrong token in header', () => {
    it('should fail with challenge when token is malformed', (done) => {
      chai.passport.use(strategy)
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal(
            'Bearer realm="Users", error="invalid_token", error_description="Invalid token (jwt malformed)"');
          done();
        })
        .request((req) => {
          req.headers.authorization = 'Bearer WRONG';
        })
        .authenticate();
    });

    it('should fail with challenge when token is expired', (done) => {
      chai.passport.use(strategy)
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal(
            'Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { subject, expiresIn: '-1m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });

    it('should fail with challenge when token signature is invalid', (done) => {
      chai.passport.use(strategy)
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal(
            'Bearer realm="Users", error="invalid_token", error_description="Invalid token (invalid signature)"');
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, `${secret}x`, { subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });

    it('should fail with challenge when token signature is not signed', (done) => {
      chai.passport.use(strategy)
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal(
            'Bearer realm="Users", error="invalid_token", error_description="Invalid token (jwt signature is required)"');
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { subject, expiresIn: '15m', algorithm: 'none' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });

    it('should fail with challenge when token audience does not match', (done) => {
      chai.passport.use(new Strategy(secret, { audience: 'foo' }, (token, cb) => cb(null, false)))
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="Invalid token (jwt audience invalid. expected: foo)"');  // eslint-disable-line
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { audience: 'bar', subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });

    it('should fail with challenge when token issuer does not match', (done) => {
      chai.passport.use(new Strategy(secret, { issuer: 'foo' }, (token, cb) => cb(null, false)))
        .fail((challenge) => {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="Invalid token (jwt issuer invalid. expected: foo)"');  // eslint-disable-line
          done();
        })
        .request((req, res, next) => {
          jwt.sign({}, secret, { issuer: 'bar', subject, expiresIn: '15m' }, (err, encoded) => {
            expect(err).to.be.null;
            req.headers.authorization = `Bearer ${encoded}`;
            next();
          });
        })
        .authenticate();
    });
  });

  describe('handling a request without credentials', () => {
    let challenge;

    before((done) => {
      chai.passport.use(strategy)
        .fail((c) => {
          challenge = c;
          done();
        })
        .request(() => {
        })
        .authenticate();
    });

    it('should fail with challenge', () => {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users"');
    });
  });
});
