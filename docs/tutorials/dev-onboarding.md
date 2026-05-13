# Developer Onboarding

This tutorial will take you through setting up your local development environment and running your first integration test.

---

## 🛠️ Prerequisites
*   **Docker** and **Docker Compose** (V2).
*   **make** utility.

## Step 1: Clone and Build
First, ensure you can build the native C components for the default architecture:

```bash
make -C devenv compile
```

## Step 2: Launch the Development Stack
We provide a "Mock Environment" that includes a fake Identity Provider (IdP) and a running OpenWrt instance.

```bash
make -C devenv up
```
*This will pull the required images and start the containers in the background.*

## Step 3: Run the Verification Suite
To ensure everything is working correctly, run the full test suite:

```bash
make -C devenv unit-test
```
*You should see a series of green checkmarks for Tiers 0 through 4.*

## Step 4: Access the Router UI
You can now access the LuCI web interface of the running container:
*   **URL:** `https://localhost:8443`
*   **Login:** Choose "Login with SSO" to trigger the flow against the Mock IdP.

---

## 🎓 Next Steps
Now that you have a working environment, learn how to [Run specific tests](../how-to/developer/testing.md) or [Contribute to documentation](../how-to/developer/documentation.md).
