import { ICredentials } from "./interfaces";

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
export function isSubset(string:string, subset:string) {
  return string.indexOf(subset) != -1;
}


