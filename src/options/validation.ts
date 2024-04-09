import Joi from 'joi';
import { AuthorizationParameters } from '../types/internal';
import {
  CallbackOptions,
  GetTokensOptions,
  SignInOptions,
  SignOutOptions,
  MonoCloudOptionsBase,
  MonoCloudRoutes,
  MonoCloudSessionOptionsBase,
  MonoCloudStateOptions,
  UserInfoOptions,
} from '../types';

const stringRequired = Joi.string().required();
const stringOptional = Joi.string().optional();
const boolRequired = Joi.boolean().required();
const boolOptional = Joi.boolean().optional();
const numRequired = Joi.number().required();
const objectOptional = Joi.object().optional();
const funcOptional = Joi.function().optional();

const sessionCookieSchema = Joi.object({
  name: stringRequired,
  path: stringRequired.uri({ relativeOnly: true }),
  domain: stringOptional,
  httpOnly: boolRequired,
  secure: boolRequired.when(Joi.ref('/appUrl'), {
    is: Joi.string().pattern(/^https:/i),
    then: Joi.valid(true).messages({
      'any.only':
        'Cookie must be set to secure when app url protocol is https.',
    }),
    otherwise: Joi.valid(false),
  }),
  sameSite: stringRequired.valid('strict', 'lax', 'none'),
  persistent: boolRequired,
}).required();

const sessionSchema: Joi.ObjectSchema<MonoCloudSessionOptionsBase> = Joi.object(
  {
    cookie: sessionCookieSchema,
    sliding: boolRequired,
    duration: numRequired.min(1),
    maximumDuration: numRequired.min(1).greater(Joi.ref('duration')),
    store: objectOptional,
  }
).required();

const stateSchema: Joi.ObjectSchema<MonoCloudStateOptions> = Joi.object({
  cookie: sessionCookieSchema,
}).required();

const authParamSchema: Joi.ObjectSchema<AuthorizationParameters> = Joi.object({
  scope: stringRequired
    .pattern(/\bopenid\b/)
    .messages({ 'string.pattern.base': 'Scope must contain openid' }),
  response_type: stringRequired.valid('code'),
  response_mode: stringOptional.valid('query', 'form_post'),
})
  .unknown(true)
  .required();

const optionalAuthParamSchema: Joi.ObjectSchema<AuthorizationParameters> =
  Joi.object({
    scope: stringOptional
      .pattern(/\bopenid\b/)
      .messages({ 'string.pattern.base': 'Scope must contain openid' }),
    response_type: stringOptional.valid('code'),
    response_mode: stringOptional.valid('query', 'form_post'),
  })
    .unknown(true)
    .optional();

const routesSchema: Joi.ObjectSchema<MonoCloudRoutes> = Joi.object({
  callback: stringRequired.uri({ relativeOnly: true }),
  backChannelLogout: stringRequired.uri({ relativeOnly: true }),
  signIn: stringRequired.uri({ relativeOnly: true }),
  signOut: stringRequired.uri({ relativeOnly: true }),
  userInfo: stringRequired.uri({ relativeOnly: true }),
}).required();

export const optionsSchema: Joi.ObjectSchema<MonoCloudOptionsBase> = Joi.object(
  {
    clientId: stringRequired,
    clientSecret: stringOptional,
    issuer: stringRequired.uri(),
    cookieSecret: stringRequired.min(8),
    appUrl: stringRequired.uri(),
    routes: routesSchema,
    clockSkew: numRequired,
    responseTimeout: numRequired.min(1000),
    usePar: boolRequired,
    postLogoutRedirectUri: stringOptional.uri({ allowRelative: true }),
    federatedLogout: boolRequired,
    userInfo: boolRequired,
    refreshUserInfo: boolRequired,
    defaultAuthParams: authParamSchema,
    session: sessionSchema,
    state: stateSchema,
    idTokenSigningAlg: Joi.string().valid(
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES384',
      'ES512'
    ),
    filteredIdTokenClaims: Joi.array<string>().items(stringRequired),
    userAgent: stringRequired,
    onBackChannelLogout: funcOptional,
    onSetApplicationState: funcOptional,
    onSessionCreating: funcOptional,
  }
);

export const signInOptionsSchema: Joi.ObjectSchema<SignInOptions> = Joi.object({
  returnUrl: stringOptional.uri({ relativeOnly: true }),
  authenticator: stringOptional,
  loginHint: stringOptional,
  register: boolOptional,
  authParams: optionalAuthParamSchema,
});

export const callbackOptionsSchema: Joi.ObjectSchema<CallbackOptions> =
  Joi.object({
    userInfo: boolOptional,
    authParams: optionalAuthParamSchema,
  });

export const userInfoOptionsSchema: Joi.ObjectSchema<UserInfoOptions> =
  Joi.object({
    refresh: boolOptional,
  });

export const signOutOptionsSchema: Joi.ObjectSchema<SignOutOptions> =
  Joi.object({
    post_logout_url: stringOptional.uri({ allowRelative: true }),
    federatedLogout: boolOptional,
    signOutParams: Joi.object().optional(),
  });

export const getTokensOptionsSchema: Joi.ObjectSchema<GetTokensOptions> =
  Joi.object({
    forceRefresh: boolOptional,
    refreshParams: optionalAuthParamSchema,
  });
