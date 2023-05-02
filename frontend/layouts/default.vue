<template>
  <div>
    <div v-if="authUser">
      <Navbar class="main" />
      <div
        v-if="
          $route.name == 'profile-slug-overview' ||
          $route.name == 'profile-slug-research' ||
          $route.name == 'profile-slug-project' ||
          $route.name == 'profile-slug-connection'
        "
      >
        <div class="container-fluid profile-header-bg main">
          <profileHeader />
        </div>
      </div>
      <div
        v-else-if="
          $route.name == 'description-slug-overview' ||
          $route.name == 'description-slug-comments'
        "
      >
        <postHeader />
      </div>
      <div
        v-else-if="
          $route.name == 'settings-account' ||
          $route.name == 'settings-twoFactorAuth' ||
          $route.name == 'settings-change_password' ||
          $route.name == 'admin-banners' ||
          $route.name == 'admin-order_banners' ||
          $route.name == 'admin-admin' ||
          $route.name == 'admin-theme'
        "
      >
        <div class="container-fluid profile-header-bg main">
          <Sidebar />
        </div>
      </div>
      <div v-else>
        <Nuxt />
      </div>
    </div>
    <div v-else>
      <Navbar class="main" />
      <div
        v-if="
          $route.name == 'description-slug-overview' ||
          $route.name == 'description-slug-comments'
        "
      >
        <postHeader />
      </div>
      <Nuxt v-else />
      <BottomContainer v-if="isFooterShow == true" />
    </div>
  </div>
</template>
<script>
import Navbar from "/components/navbar";
import BottomContainer from "/components/footer";
import profileHeader from "/components/profileHeader";
import ProfileNav from "/components/profileNav";
import postHeader from "/components/postHeader";
import Sidebar from "/components/sidebar";

const { io } = require("socket.io-client");

export default {
  components: {
    Navbar,
    profileHeader,
    ProfileNav,
    BottomContainer,
    postHeader,
    Sidebar,
  },
  data() {
    return {
      isHeaderShow: true,
      isFooterShow: true,
    };
  },

  methods: {
    isHeaderShowChange() {
      if (
        this.$route.name == "login" ||
        this.$route.name == "register" ||
        this.$route.name == "index" ||
        this.$route.name == "research" ||
        this.$route.name == "department"
      ) {
        this.isHeaderShow = true;
      } else this.isHeaderShow = false;
    },
    isFooterShowChange() {
      if (
        this.$route.name == "register" ||
        this.$route.name == "login" ||
        this.$route.name == "index" ||
        this.$route.name == "auth-account-activation" ||
        this.$route.name == "auth-forgot_password" ||
        this.$route.name == "auth-otp" ||
        this.$route.name == "auth-reset_password"
      ) {
        this.isFooterShow = true;
      } else this.isFooterShow = false;
    },
  },
  async mounted() {
    const socket = io("http://127.0.0.1:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
    // this.$store.commit("setSocket", socket);
  },
  watch: {
    "$route.name": function (newVal, oldVal) {
      // watch it

      this.isHeaderShowChange();
      this.isFooterShowChange();
    },
  },
  async created() {
    console.log("inside default");
    const res = await this.callApi("get", "/api/get_theme");

    if (res.status == 200) {
      console.log("inside 200");
      console.log(res.data);

      this.$store.commit("setTheme", res.data);
    }
  },
};
</script>
