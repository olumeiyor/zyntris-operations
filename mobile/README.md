# Zyntris Operations mobile

This is a standalone Expo / React Native client for iOS and Android. It lives under `mobile/` and is deliberately excluded from the Vite/Cloudflare Worker build, so it does not replace or alter the web application at `app.zyntris.org`.

The client connects to the existing production API. It provides organization sign-in, an operations snapshot, request creation and review, role-gated payroll run review/final approval/payment-status recording, and a persistent in-app notifications inbox. Notifications are scoped to the signed-in user and organization. Request approvers also receive approval-pending email through the existing Brevo Worker integration. Mobile access tokens are hashed in D1, expire after 12 hours, and are stored on device using Expo SecureStore.

## Run locally

```sh
cd mobile
npm install
npx expo start
```

Use Expo Go for UI development or an iOS Simulator / Android Emulator. Device sign-in uses the deployed HTTPS API at `https://app.zyntris.org`.
The current Expo SDK requires Node.js 22.13 or newer.

## Store builds

Install and sign into EAS CLI, then create the EAS project and set its returned project ID in `app.json` under `expo.extra.eas.projectId`. Configure Apple signing in App Store Connect and Android signing / Play Console submission credentials before running:

```sh
npm run build:ios
npm run build:android
```

Builds can be submitted from EAS after the respective Apple Developer and Google Play Console accounts, store listings, screenshots, privacy disclosures, and review materials are ready. The repository is prepared for those builds but has not been submitted to either store.

## API boundary

The app calls `/api/mobile/*`. Only that API prefix accepts bearer session tokens; existing browser routes continue to require the existing secure cookie. The mobile login endpoint creates a normal, revocable D1 session. Do not place service credentials or the Brevo key in the app bundle.

The notification inbox is in-app/persistent. OS-level push delivery is not enabled yet; that requires registering device push tokens and configuring Apple APNs and Android FCM credentials in EAS.
