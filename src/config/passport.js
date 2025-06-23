import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as TwitterStrategy } from 'passport-twitter';
import { getUserBySocial, createUser, getUserByEmail } from '../services/userServiceClient.js';

export default function (passport) {
  // Local strategy
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
      // You should also update this to use user-service if needed
      try {
        // Example: call user-service for user lookup and password check
        // let user = await getUserByEmail(email);
        // if (!user) return done(null, false, { message: 'Incorrect email.' });
        // const isMatch = await comparePassword(password, user.password);
        // if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
        // return done(null, user);
        return done(new Error('LocalStrategy not implemented for microservices'));
      } catch (err) {
        return done(err);
      }
    })
  );

  // Google OAuth
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await getUserBySocial('google', profile.id);
          if (!user) {
            // Try to find by email if not found by social ID
            const email = profile.emails && profile.emails[0] && profile.emails[0].value;
            if (email) {
              let userByEmail = await getUserByEmail(email);
              if (userByEmail) {
                // Link the social ID to the existing user (admin endpoint)
                const updateUrl = `${process.env.USER_SERVICE_URL}/${userByEmail._id}`;
                // TODO: Use admin token for PATCH if required by your API
                const updateRes = await fetch(updateUrl, {
                  method: 'PATCH',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ social: { google: { id: profile.id } }, isEmailVerified: true }),
                });
                if (updateRes.ok) {
                  user = await updateRes.json();
                  if (!user || !user._id) {
                    console.error('PATCH /users/:id did not return user with _id:', user);
                    return done(new Error('Failed to link Google ID: no user _id in response'));
                  }
                } else {
                  const text = await updateRes.text();
                  console.error('Failed to link Google ID to existing user:', updateRes.status, text);
                  return done(new Error('Failed to link Google ID to existing user'));
                }
              } else {
                // No user by email, create new
                user = await createUser({ email, social: { google: { id: profile.id } }, isEmailVerified: true });
              }
            } else {
              // No email, cannot proceed
              return done(new Error('No email found in Google profile'));
            }
          }
          if (!user || !user._id) {
            console.error('GoogleStrategy: User-service did not return a user with _id for Google login', user);
            return done(new Error('User-service did not return a user with _id for Google login'));
          }
          // Return user object with provider/id for downstream callback
          return done(null, { ...user, provider: 'google', id: profile.id });
        } catch (err) {
          console.error('GoogleStrategy error:', err);
          return done(err);
        }
      }
    )
  );

  // Facebook OAuth
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL,
        profileFields: ['id', 'emails', 'name'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ 'social.facebook.id': profile.id });
          if (!user) {
            user = await User.create({ email: profile.emails[0].value, social: { facebook: { id: profile.id } } });
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // Twitter OAuth
  passport.use(
    new TwitterStrategy(
      {
        consumerKey: process.env.TWITTER_CONSUMER_KEY,
        consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
        callbackURL: process.env.TWITTER_CALLBACK_URL,
        includeEmail: true,
      },
      async (token, tokenSecret, profile, done) => {
        try {
          let user = await User.findOne({ 'social.twitter.id': profile.id });
          if (!user) {
            user = await User.create({ email: profile.emails[0].value, social: { twitter: { id: profile.id } } });
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
}
