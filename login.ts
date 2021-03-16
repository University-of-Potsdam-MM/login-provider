/* External dependencies */
import { Injectable } from "@angular/core";
import { HttpClient, HttpHeaders, HttpParams } from "@angular/common/http";
import { Observable, ReplaySubject } from "rxjs";
/* Imports from this module (in same directory) */
import {
  ISession,
  ICredentials,
  IOIDCLoginResponse,
  ELoginErrors,
  ILoginConfig_OIDC,
  IOIDCRefreshResponseObject,
  IOIDCUserInformationResponse,
} from "./interfaces";
import { WebHttpUrlEncodingCodec } from "./lib";

// set to true to see output
const debugMode = true;

/**
 * Prints text only if global debug variable has been set
 *
 * @param text
 */
export function debug(text) {
  if (debugMode) {
    console.log(`[LoginProvider]:${text}`);
  }
}

/**
 * LoginProvider
 *
 * only the login(credentials, authConfig) method can be called from the outside.
 * The 'authConfig' parameter should contain a member named 'method' having one
 * of the following values
 *
 *  - "oidc" (for executing OpenID connect)
 *
 */
@Injectable()
export class UPLoginProvider {
  constructor(public http: HttpClient) {}

  /**
   * executes OIDC login
   *
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  public oidcLogin(
    oidcCredentials: ICredentials,
    loginConfig: ILoginConfig_OIDC
  ): Observable<ISession> {
    debug("[oidcLogin] Doing oidcLogin");

    const tokenUrl: string = loginConfig.tokenUrl;

    const oidcHeaders: HttpHeaders = new HttpHeaders()
      .append("Authorization", loginConfig.accessToken)
      .append("Content-Type", loginConfig.contentType);

    const oidcParams: HttpParams = new HttpParams({
      encoder: new WebHttpUrlEncodingCodec(),
    })
      .append("grant_type", loginConfig.grantType_password)
      .append("username", oidcCredentials.username)
      .append("password", oidcCredentials.password)
      .append("scope", loginConfig.scope);

    const rs = new ReplaySubject<ISession>();

    this.http.post(tokenUrl, oidcParams, { headers: oidcHeaders }).subscribe(
      (response: IOIDCLoginResponse) => {
        // create session object with access_token as token, but also attach
        // the whole response in case it's needed
        rs.next({
          credentials: oidcCredentials,
          token: response.access_token,
          oidcTokenObject: response,
          timestamp: new Date(),
        });
        rs.complete();
      },
      (oidcError) => {
        // Authentication error
        // TODO: Add typing for errors?
        if (
          (oidcError &&
            oidcError.error &&
            oidcError.error.error === "invalid_grant") ||
          oidcError.status === 401
        ) {
          rs.error({
            reason: ELoginErrors.AUTHENTICATION,
            description: "oidc authentication error",
            error: oidcError,
          });
        } else {
          rs.error({
            reason: ELoginErrors.NETWORK,
            error: oidcError,
          });
        }
      }
    );

    return rs;
  }

  /**
   * refreshes OIDC token with refreshToken and the loginConfig. Returns an object
   * containing new OIDC-Response-Object and a timestamp.
   *
   * @param refreshToken
   * @param loginConfig
   */
  public oidcRefreshToken(
    refreshToken: string,
    loginConfig: ILoginConfig_OIDC
  ): Observable<IOIDCRefreshResponseObject> {
    debug("[oidcLogin] Doing oidc token refresh");

    const tokenUrl: string = loginConfig.tokenUrl;

    const oidcHeaders: HttpHeaders = new HttpHeaders()
      .append("Authorization", loginConfig.accessToken)
      .append("Content-Type", loginConfig.contentType);

    const oidcParams: HttpParams = new HttpParams({
      encoder: new WebHttpUrlEncodingCodec(),
    })
      .append("grant_type", loginConfig.grantType_refresh)
      .append("refresh_token", refreshToken);

    const rs = new ReplaySubject<IOIDCRefreshResponseObject>();

    this.http.post(tokenUrl, oidcParams, { headers: oidcHeaders }).subscribe(
      (response: IOIDCLoginResponse) => {
        // create session object with access_token as token, but also attach
        // the whole response in case it's needed
        rs.next({
          oidcTokenObject: response,
          timestamp: new Date(),
        });
        rs.complete();
      },
      (response) => {
        console.log(response);
        // Authentication error
        if (
          response &&
          response.error &&
          response.error.error === "invalid_grant"
        ) {
          let errorDescription;
          let authError;
          if (
            response.error &&
            response.error.error_description &&
            response.error.error
          ) {
            errorDescription = response.error.error_description;
            authError = response.error.error;
          }

          rs.error({
            reason: ELoginErrors.AUTHENTICATION,
            error: authError,
            description: errorDescription,
          });
        } else {
          rs.error({ reason: ELoginErrors.NETWORK });
        }
      }
    );

    return rs;
  }

  /**
   * returns information about user via OIDC
   *
   * @param userToken
   * @param loginConfig
   */
  public oidcGetUserInformation(
    session: ISession,
    loginConfig: ILoginConfig_OIDC
  ): Observable<IOIDCUserInformationResponse> {
    debug("[oidcLogin] Retrieving OIDC user information");

    const userInfoUrl: string = loginConfig.userInformationUrl;

    const oidcHeaders: HttpHeaders = new HttpHeaders().append(
      "Authorization",
      `${session.oidcTokenObject.token_type} ${session.oidcTokenObject.access_token}`
    );

    const rs = new ReplaySubject<IOIDCUserInformationResponse>();

    this.http
      .get(userInfoUrl, {
        headers: oidcHeaders,
        params: { schema: loginConfig.userInfoParams.schema },
      })
      .subscribe(
        (response: IOIDCUserInformationResponse) => {
          rs.next(response);
          rs.complete();
        },
        (error) => {
          console.log(error);
          // Authentication error
          if (error && error.error && error.error.error === "invalid_grant") {
            rs.error({ reason: ELoginErrors.AUTHENTICATION });
          } else {
            rs.error({ reason: ELoginErrors.NETWORK });
          }
        }
      );

    return rs;
  }
}
