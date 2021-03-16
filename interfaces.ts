/** Errors that will be used by LoginProvider */
export enum ELoginErrors {
  AUTHENTICATION,
  TECHNICAL,
  NETWORK,
  UNKNOWN_METHOD,
  UNKNOWN_ERROR,
  TIMEOUT,
}

/** Defines a LoginRequest that is given to each login method */
export interface ILoginRequest {
  credentials: ICredentials;
  loginAttemptStarted: boolean;
  oidcConfig?: ILoginConfig_OIDC;
}

/** Server response for ordinary credentials login */
export interface ICredentialsLoginResponse {
  token?: string;
}

/** Server response for OIDC login */
export interface IOIDCLoginResponse {
  access_token: string;
  refresh_token: string;
  scope: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
}

/** Server response for OIDC user information */
export interface IOIDCUserInformationResponse {
  sub: string;
  name: string;
  given_name: string;
  family_name: string;
  email: string;
}

/** Credentials used for logging in */
export interface ICredentials {
  username: string;
  password: string;
}

/** Interface for the session to be saved in storage */
export interface ISession {
  token: string;
  credentials?: ICredentials;
  timestamp?: Date;
  oidcTokenObject?: IOIDCLoginResponse;
  // Reflect.UP v7+
  courseID?: string;
  courseName?: string;
  courseFac?: string;
  hexColor?: string;
  isHidden?: boolean;
}

export interface IOIDCRefreshResponseObject {
  timestamp: Date;
  oidcTokenObject: IOIDCLoginResponse;
}

/* ~~~ config ~~~ */
export interface IPluginUrlParams {
  service: string;
  passport: string;
}

export interface AccessToken {
  accessToken: string;
}

/* OIDC */
export interface ILoginConfig_OIDC {
  tokenUrl: string;
  accessToken: string;
  contentType: string;
  scope: string;
  grantType_password: string;
  grantType_refresh?: string;
  userInfoParams?: IUserInfoParams;
  userInformationUrl?: string;
}

export interface IUserInfoParams {
  schema: string;
}
