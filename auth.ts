import * as eta from "./eta";
import * as db from "./db";
import * as passport from "passport";
const CasStrategy = require("passport-cas2").Strategy;

export default class CasAuthProvider extends eta.IAuthProvider {
    public getPassportStrategy(): passport.Strategy {
        return new CasStrategy({
            casURL: eta.config.modules["cre-auth-cas"].url
        }, (username: string, profile: CasProfile, done: (err: Error, user?: db.User) => void) => {
            this.onPassportVerify(username, profile).then((person: db.User) => {
                done(undefined, person);
            }).catch(err => {
                done(err);
            });
        });
    }

    private async onPassportVerify(username: string, profile: CasProfile): Promise<db.User> {
        const user: db.User = await db.user().findOne({ username });
        if (user) return user;
        else return <any>{ username };
    }

    public async onPassportLogin(user: db.User): Promise<void> {
        if (user.id !== undefined) {
            // user has a Person entry
            return;
        }
        this.req.session["casUsername"] = user.username;
        await this.saveSession();
        this.redirect("/auth/cas/register");
    }

    public getConfigurationURL(): string {
        return "/auth/cas/configure";
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
