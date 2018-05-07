import { Injectable } from '@angular/core';
import { IAuthorization } from '../../lib/interfaces/config.json';
import { InAppBrowser, InAppBrowserEvent, InAppBrowserObject } from "@ionic-native/in-app-browser";
import { HttpClient, HttpHeaders, HttpParams, HttpErrorResponse } from '@angular/common/http';
import {
  ICredentialsLoginResponse,
  ISession,
  ICredentials,
  IOIDCLoginResponse
} from '../../lib/interfaces';
import { WebHttpUrlEncodingCodec } from '../../lib/util';
import { Observable } from "rxjs/Observable";
import { Observer } from "rxjs/Observer";

// set to true to see output
var debugMode:boolean = true;

/**
 * cleans provided username. Puts it to lowercase and removes optional mail suffix.
 * It is expected that credentials given to a LoginProvider have been cleaned by
 * this method.
 * @param {ICredentials} credentials
 * @return {ICredentials} cleaned credentials
 */
export function cleanCredentials(credentials:ICredentials):ICredentials{
  let atChar = "@";

  // only username needs cleaning, actually
  let cleanedUsername:string = credentials.username.toLowerCase().substring(
    0,
    credentials.username.includes(atChar)
      ? credentials.username.lastIndexOf(atChar)
      : credentials.username.length
  );

  return {
    username: cleanedUsername,
    password: credentials.password
  }
}

/**
 * returns whether 'subset' is a subst of 'string'. Actually just a shorter way
 * for calling '.indexOf(...) != -1'
 * @param {string} string
 * @param {string} subset
 * @returns {boolean}
 */
function isSubset(string:string, subset:string) {
  return string.indexOf(subset) != -1;
}

/** Defines a LoginProvider, not that much right now, but can't hurt */
export interface ILoginProvider {
  login(credentials:ICredentials, authConfig:IAuthorization):Observable<ISession>;
}

/**
 * Prints text only if global debug variable has been set
 * @param text
 */
export function debug(text) {
  if(debugMode) {
    console.log(`[LoginProvider]: ${text}`);
  }
}

/** Errors that will be used by LoginProvider */
export enum ELoginErrors {
  AUTHENTICATION, TECHNICAL, NETWORK, UNKNOWN_METHOD, UNKNOWN_ERROR
}

/** Defines a LoginRequest that is given to each login method */
export interface ILoginRequest {
  credentials:ICredentials,
  browser?:InAppBrowserObject,
  loginAttemptStarted:boolean,
  authConfig:IAuthorization
}

/** Single action that can be triggered by an SSO browser event */
export interface IAction {
  event: string;
  condition(event:InAppBrowserEvent, loginRequest:ILoginRequest): boolean;
  action(event:InAppBrowserEvent, loginRequest:ILoginRequest, observer:Observer<ISession>):void;
}

/**
 * LoginProvider
 *
 * only the login(credentials, authConfig) method can be called from the outside.
 * The 'authConfig' parameter should contain a member named 'method' having one
 * of the following values
 *
 *  - "sso" (for executing Single Sign On)
 *  - "oidc" (for executing OpenID connect)
 *  - "credentials" (for executing normal username/password login)
 *
 * the LoginProvider will execute the right method internally and return the
 * created session (or an error).
 */
@Injectable()
export class UPLoginProvider implements ILoginProvider {

  // URLS used in SSO login
  private ssoURLs = {
    // TODO: outsource those urls to config
    plugin: "https://moodle2.uni-potsdam.de/local/mobile/launch.php?service=local_mobile&passport=1002",
    login: "https://moodle2.uni-potsdam.de/login/index.php",
    token: "moodlemobile://token=",
    idpBase: "https://idp.uni-potsdam.de/idp/profile/SAML2/Redirect/SSO",
    idp: "https://idp.uni-potsdam.de/idp/Authn/UserPassword",
    attributeRelease: "https://idp.uni-potsdam.de/idp/uApprove/AttributeRelease"
  };

  // events that can occur in InAppBrowser during SSO login
  private ssoBrowserEvents = {
    loadStart:  "loadstart",
    loadStop:   "loadstop",
    loadError:  "loaderror",
    exit:       "exit"
  };

  // predefined actions that will be used
  private ssoActions:IAction[] = [
    {
      // obtains token from URL
      event: this.ssoBrowserEvents.loadStart,
      condition: (event, loginRequest) => {
        return isSubset(event.url, this.ssoURLs.token) ||
          isSubset(event.url, ("http://" + this.ssoURLs.token))
      },
      action: (event, loginRequest, observer) => {
        if(isSubset(event.url, this.ssoURLs.token) ||
          isSubset(event.url, ("http://" + this.ssoURLs.token))) {

          let token = event.url;
          token = token.replace("http://", "");
          token = token.replace(this.ssoURLs.token, "");
          debug(`ssoLogin: token ${token}`);
          try {
            token = atob(token);

            // Skip the passport validation, just trust the token
            token = token.split(":::")[1];
            debug(`ssoLogin: Moodle token found: ${token}`);

            let session:ISession = {
              credentials:  loginRequest.credentials,
              token:        token
            };

            debug("ssoLogin: Session created");

            observer.next(session);
            observer.complete();
          } catch (error) {
            // TODO: check what caused the error
            observer.error({reason: ELoginErrors.TECHNICAL, error: error});
          }
        }
      }
    },
    {
      // checks whether a login form is present and then injects code for login
      event: this.ssoBrowserEvents.loadStop,
      condition: (event, loginRequest) => {
        return isSubset(event.url, this.ssoURLs.idpBase) &&
          !loginRequest.loginAttemptStarted
      },
      action: async (event, loginRequest, subject) => {
        debug("ssoLogin: Testing for login form");

        // Test for a login form
        let testForLoginForm = '$("form#login").length;';
        let length = await loginRequest.browser.executeScript({ code: testForLoginForm });

        if(length[0] >= 1) {
          debug("ssoLogin: Login form present");

          // Create code for executing login in browser
          let enterCredentials =
            `$("form#login #username").val(\'${loginRequest.credentials.username}\');
             $("form#login #password").val(\'${loginRequest.credentials.password}\');
             $("form#login .loginbutton").click();`;

          loginRequest.loginAttemptStarted = true;

          debug("ssoLogin: Injecting login code now");
          loginRequest.browser.executeScript({code: enterCredentials});
        }
      }
    },
    {
      //
      event: this.ssoBrowserEvents.loadError,
      condition: (event, loginRequest) => { return true },
      action: (event, loginRequest, observer) => {
        // TODO: something should be done here, I guess
      }
    },
    {
      // happens when user closes browser
      event: this.ssoBrowserEvents.exit,
      condition: () => { return true },
      action: (event, loginRequest, observer) => {
        observer.error({
          reason: ELoginErrors.TECHNICAL,
          description: "User closed browser"
        });
      }
    }
  ];

  constructor(
      public http: HttpClient,
      public inAppBrowser: InAppBrowser) {
  };

  /**
   * performs the correct login method depending on the `method` parameter and
   * returns an Observable<ISession> containing the session.
   * @param {ICredentials} credentials
   * @param {IAuthorization} authConfig
   * @returns {Promise<ISession>}
   */
  public login(credentials:ICredentials, authConfig:IAuthorization): Observable<ISession> {

    let loginRequest:ILoginRequest = {
      credentials: cleanCredentials(credentials),
      authConfig: authConfig,
      loginAttemptStarted: false
    };

    return Observable.create(
      observer => {
        // TODO: Maybe find way to make this prettier
        switch(authConfig.method) {
          case "credentials": {
            this.credentialsLogin(loginRequest, observer);
            break;
          }
          case "sso": {
            this.ssoLogin(loginRequest, observer);
            break;
          }
          case "oidc": {
            this.oidcLogin(loginRequest, observer);
            break;
          }
          default: {
            observer.error({
              reason: ELoginErrors.UNKNOWN_METHOD,
              message: `Unknown method '${authConfig.method}'`
            });
            break;
          }
        }
      }
    );
  }

  /**
   * Handles ssoBrowserEvents by executing defined actions if event type matches
   * and condition function of action returns true
   *
   * @param {InAppBrowserEvent} event
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  private handleSsoEvent(event:InAppBrowserEvent,
                         loginRequest:ILoginRequest,
                         observer:Observer<ISession>) {

    // test all defined ssoActions
    for(let ssoAction of this.ssoActions) {
      // execute action if event type matches and condition functions returns true
      if (ssoAction.event == event.type && ssoAction.condition(event, loginRequest)) {
        ssoAction.action(event, loginRequest, observer);
      }
    }
  }

  /**
   * Performs a SSO login by creating an InAppBrowser object and attaching
   * listeners to it. When SSO login has been performed the given observer is
   * used to return the created ISession (happens in ssoAction)
   *
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  private ssoLogin(loginRequest:ILoginRequest, observer:Observer<ISession>) {
    debug("Doing ssoLogin");

    if(!loginRequest.browser) {
      debug("ssoLogin: Browser is undefined, will create one");
      // If no browser is given create browser object by loading URL
      loginRequest.browser = this.inAppBrowser.create(
        this.ssoURLs.plugin, "_blank", {clearcache: "yes", clearsessioncache: "yes"}
      );
    }

    Observable.create(
      observer => {
        for(let event in this.ssoBrowserEvents) {
          loginRequest.browser.on(this.ssoBrowserEvents[event]).subscribe(
            (event: InAppBrowserEvent) => this.handleSsoEvent(event, loginRequest, observer)
          );
        }
      }
    ).subscribe(
      session => {
        // TODO: use cleanup function here?
        debug("ssoLogin: Success, closing browser now");
        loginRequest.browser.close();
        setTimeout(
          ()=> {
            observer.next(session);
          }, 2000
        );
      },
      error => {
        debug("ssoLogin: Failed, closing browser now");
        loginRequest.browser.close();
        setTimeout(
          ()=> {
            observer.error(error);
          }, 2000
        );
      }
    );
  }

  /**
   * Performs login with provided loginRequest. Returns created session or error
   * with provided observer object.
   *
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  private credentialsLogin(loginRequest:ILoginRequest, observer:Observer<ISession>): void {
    debug("Doing credentialsLogin");

    let url:string = loginRequest.authConfig.moodleLoginEndpoint;

    let headers:HttpHeaders = new HttpHeaders()
      .append("Authorization",       loginRequest.authConfig.accessToken);

    let params:HttpParams = new HttpParams({encoder: new WebHttpUrlEncodingCodec()})
      .append("username",           loginRequest.credentials.username)
      .append("password",           loginRequest.credentials.password)
      .append("service",            loginRequest.authConfig.service)
      .append("moodlewsrestformat", loginRequest.authConfig.moodlewsrestformat);

    this.http.get(url, {headers: headers, params: params}).subscribe(
      (response:ICredentialsLoginResponse) => {
        if(response.token) {
          observer.next({
            credentials:  loginRequest.credentials,
            token:        response.token
          });
          observer.complete();
        } else {
          observer.error({reason: ELoginErrors.AUTHENTICATION});
        }
      },
      (error:HttpErrorResponse) => {
        // some other error
        observer.error({reason: ELoginErrors.UNKNOWN_ERROR, error: error});
      }
    );
  }

  /**
   * executes OIDC login
   * @param {ILoginRequest} loginRequest
   * @param {Observer<ISession>} observer
   */
  private oidcLogin(loginRequest:ILoginRequest, observer:Observer<ISession>): void {
    debug("Doing oidcLogin");

    // TODO: outsource stuff to config
    let url:string = "https://apiup.uni-potsdam.de/endpoints/token";

    let headers:HttpHeaders = new HttpHeaders()
      .append("Authorization",      "Basic Vk9hQmRLT2N0U1FraTRmcFpZdWRXOTZQSDc0YTpWSXA2aXhmMVBZTXdRUE0xcUxhUnliNVQ4Nllh")
      .append("Content-Type",       "application/x-www-form-urlencoded");

    let params:HttpParams = new HttpParams({encoder: new WebHttpUrlEncodingCodec()})
      .append("grant_type",         "password")
      .append("username",           loginRequest.credentials.username)
      .append("password",           loginRequest.credentials.password)
      .append("scope",              "openid");

    this.http.post(url, params, {headers: headers}).subscribe(
      (response:IOIDCLoginResponse) => {
        // create session object with access_token as token, but also attach
        // the whole response in case it's needed
        observer.next({
          credentials:      loginRequest.credentials,
          token:            response.access_token,
          oidcTokenObject:  response
        });
        observer.complete();
      },
      (error) => {
        // Authentication error
        // TODO: Add typing for errors?
        if(error.status = 401) {
          observer.error({reason: ELoginErrors.AUTHENTICATION});
        }
      }
    );
  }

  /**
   * Allows adding custom sso actions from outside
   * @param {IAction} ssoAction
   */
  public addSSOaction(ssoAction:IAction){
    this.ssoActions.push(ssoAction);
  }


}
