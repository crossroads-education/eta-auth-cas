import * as eta from "./eta";
import * as db from "./db";
import * as passport from "passport";
const CasStrategy = require("passport-cas2").Strategy;

export default class CasAuthProvider extends eta.IAuthProvider {
    public getPassportStrategy(): passport.Strategy {
        return new CasStrategy({
            casURL: eta.config.auth.cas.url
        }, (username: string, profile: CasProfile, done: (err: Error, user?: db.Person) => void) => {
            this.onPassportVerify(username, profile).then((person: db.Person) => {
                done(undefined, person);
            }).catch(err => {
                done(err);
            });
        });
    }

    private async onPassportVerify(username: string, profile: CasProfile): Promise<db.Person> {
        const person: db.Person = await db.person().findOne({ username });
        if (person) return person;
        else return <any>{ username };
    }

    public async onPassportLogin(person: db.Person): Promise<void> {
        if (person.id !== undefined) {
            // user has a Person entry
            return;
        }
        this.req.session["casUsername"] = person.username;
        await this.saveSession();
        this.redirect("/auth/cas/register");
    }
}

interface CasProfile {
    provider: string;
    id: string;
    displayName: string;
    name: {
        familyName: string;
        givenName: string;
        middleName: string;
    };
    emails: string[];
    safeword: string[];
    passphrase: string[];
}
