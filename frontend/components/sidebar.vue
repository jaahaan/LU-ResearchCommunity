<template>
  <div class="profile-section col-lg-10 col-md-8 m-auto">
    <div
      class="navbar-mobile--wrapper d-lg-none"
      v-bind:class="{ active: isSidebar }"
    >
      <div class="navbar-mobile profile-menu">
        <h1 class="settings px-4">
          <div>
            <i class="fa-solid fa-gear"></i>
            Settings
          </div>
          <a>
            <i class="lni lni-close"></i>
          </a>
        </h1>

        <ul class="profile-menu--list">
          <li class="profile-menu--list---item">
            <nuxt-link
              class="menu-link"
              aria-current="page"
              to="/settings/account"
              ><i class="fa-solid fa-user"></i>
              <h4>Account</h4></nuxt-link
            >
          </li>
          <li class="profile-menu--list---item">
            <nuxt-link
              class="menu-link"
              aria-current="page"
              to="/settings/change_password"
            >
              <i class="fa-solid fa-key"></i>
              <h4>Change Password</h4></nuxt-link
            >
          </li>
          <li class="profile-menu--list---item">
            <nuxt-link
              class="menu-link"
              aria-current="page"
              to="/settings/twoFactorAuth"
            >
              <i class="fa-solid fa-shield-halved"></i>
              <div>
                <h4>Use two-factor authentication</h4>
                <span
                  :class="[
                    authUser.twoFactor == 'On' ? 't_clr__green' : 't_clr__red',
                  ]"
                  >{{ authUser.twoFactor }}</span
                >
              </div>
            </nuxt-link>
          </li>
          <div v-if="authUser.userType == 'admin'">
            <li class="profile-menu--list---item">
              <nuxt-link class="menu-link" aria-current="page" to="/admin/admin"
                ><i class="fa-solid fa-users"></i>
                <h4>Admins</h4></nuxt-link
              >
            </li>
            <li class="profile-menu--list---item">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                to="/admin/banners"
                ><i class="fa-solid fa-image"></i>
                <h4>Change Banners</h4></nuxt-link
              >
            </li>

            <li class="profile-menu--list---item">
              <nuxt-link class="menu-link" aria-current="page" to="/admin/theme"
                ><i class="fa-solid fa-palette"></i>
                <h4>Change Theme</h4></nuxt-link
              >
            </li>
          </div>
        </ul>
      </div>
    </div>
    <div class="profile-menu d-lg-none">
      <div class="settings">
        <i
          class="fa-solid fa-bars mt-2 c-pointer"
          v-on:click="showSidebar()"
          ref="sidebarSource"
        ></i>
      </div>
    </div>
    <div class="profile-menu d-lg-block d-none">
      <h1 class="settings">
        <div>
          <i class="fa-solid fa-gear"></i>
          Settings
        </div>
        <div></div>
      </h1>

      <ul class="profile-menu--list">
        <li class="profile-menu--list---item">
          <nuxt-link
            class="menu-link"
            aria-current="page"
            to="/settings/account"
            ><i class="fa-solid fa-user"></i>
            <h4>Account</h4></nuxt-link
          >
        </li>
        <li class="profile-menu--list---item">
          <nuxt-link
            class="menu-link"
            aria-current="page"
            to="/settings/change_password"
          >
            <i class="fa-solid fa-key"></i>
            <h4>Change Password</h4></nuxt-link
          >
        </li>
        <li class="profile-menu--list---item">
          <nuxt-link
            class="menu-link"
            aria-current="page"
            to="/settings/twoFactorAuth"
          >
            <i class="fa-solid fa-shield-halved"></i>
            <div>
              <h4>Use two-factor authentication</h4>
              <span
                :class="[
                  authUser.twoFactor == 'On' ? 't_clr__green' : 't_clr__red',
                ]"
                >{{ authUser.twoFactor }}</span
              >
            </div>
          </nuxt-link>
        </li>
        <div v-if="authUser.userType == 'admin'">
          <li class="profile-menu--list---item">
            <nuxt-link class="menu-link" aria-current="page" to="/admin/admin"
              ><i class="fa-solid fa-users"></i>
              <h4>Admins</h4></nuxt-link
            >
          </li>
          <li class="profile-menu--list---item">
            <nuxt-link class="menu-link" aria-current="page" to="/admin/banners"
              ><i class="fa-solid fa-image"></i>
              <h4>Change Banners</h4></nuxt-link
            >
          </li>

          <li class="profile-menu--list---item">
            <nuxt-link class="menu-link" aria-current="page" to="/admin/theme"
              ><i class="fa-solid fa-palette"></i>
              <h4>Change Theme</h4></nuxt-link
            >
          </li>
        </div>
      </ul>
    </div>

    <!-- profile description -->
    <div class="profile-description menu-item">
      <div class="menu-item-box">
        <Nuxt />
      </div>
    </div>
  </div>
</template>

<script>
export default {
  middleware: "auth",
  data() {
    return {
      isSidebar: false,
    };
  },
  methods: {
    showSidebar() {
      this.isSidebar = true;
    },
    hideSidebar(e) {
      if (this.isSidebar) {
        let target = e.target;
        var source = this.$refs.sidebarSource;

        if (!source.contains(target)) {
          this.isSidebar = false;
          this.keyword = "";
        }
      }
    },
  },

  mounted() {
    document.addEventListener("click", this.hideSidebar);
  },
  beforeDestroy() {
    document.removeEventListener("click", this.hideSidebar);
  },
};
</script>

<style scoped>
.title {
  color: Black;
  font-size: 24px;
  margin-top: 10px;
}
.menu-items {
  display: flex;
  flex-direction: column;
  margin-top: 40px;
  margin-left: 6px;
}
.menu-items > * {
  margin-top: 60px;
}
.side-btn {
  border: none;
  padding: 16px 0px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 500;
  color: white;
  background-color: transparent;
}
.side-btn:focus {
  outline: none;
}
.side-btn.active {
  position: relative;
  background-color: white;
  color: teal;
  font-weight: 600;
  margin-left: 10px;
  border-radius: 30px 0 0 30px;
}
.side-btn.active::before {
  top: -30px;
}
.side-btn.active::after {
  bottom: -30px;
}
.side-btn.active::before,
.side-btn.active::after {
  position: absolute;
  content: "";
  right: 0;
  height: 30px;
  width: 30px;
  background-color: white;
}
.side-btn.active .link-container::before {
  top: -60px;
}
.side-btn.active .link-container::after {
  bottom: -60px;
  z-index: 99;
}
.side-btn.active .link-container::before,
.side-btn.active .link-container::after {
  position: absolute;
  content: "";
  right: 0px;
  height: 60px;
  width: 60px;
  border-radius: 50%;
  background-color: teal;
}
.active {
  display: block;
}
</style>
