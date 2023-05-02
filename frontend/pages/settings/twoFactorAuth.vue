<template>
  <div class="connection--item mt-40">
    <h5 class="post-title">
      <div>
        <i
          :class="[
            authUser.twoFactor == 'On' ? 'green' : 'red',
            'fa-solid fa-lock',
          ]"
        ></i
        >Two-factor authentication is
        <span
          :class="[authUser.twoFactor == 'On' ? 't_clr__green' : 't_clr__red']"
          >{{ authUser.twoFactor }}</span
        >
      </div>
    </h5>
    <p class="post-sub-title">
      We'll ask for a verification code via your security method.
    </p>
    <button
      :class="[authUser.twoFactor == 'On' ? 'tf tf__danger' : 'tf tf__success']"
      @click="showModal"
    >
      {{ authUser.twoFactor == "On" ? "Turn Off" : "Turn On" }}
    </button>
    <div class="b_bottom"></div>
    <h5 class="post-title">
      <div>Your security method</div>
    </h5>
    <div class="post-content">
      <i class="fa-solid fa-envelope"></i>
      <div>
        <p class="post-sub-title">Email</p>
        <p>{{ authUser.email }}</p>
      </div>
    </div>
    <Modal v-model="activeModal" width="360">
      <p slot="header" style="color: #7da2a9; text-align: center">
        <Icon type="close"></Icon>
        <span> {{ btnTitle }}</span>
      </p>
      <div style="text-align: center">{{ title }} {{ btnTitle }}</div>
      <div slot="footer">
        <Button
          style="color: #7da2a9"
          size="large"
          long
          :loading="sending"
          @click="update"
        >
          {{ btnTitle }}
        </Button>
      </div>
    </Modal>
  </div>
</template>

<script>
import { mapGetters } from "vuex";

export default {
  middleware: "auth",

  data() {
    return {
      // isLoading: true,
      activeModal: false,
      sending: false,

      title: "",
      btnTitle: "",
      data: {
        status: "",
      },
    };
  },

  methods: {
    showModal() {
      if (this.authUser.twoFactor == "On") {
        this.btnTitle = "Turn Off";
      } else {
        this.btnTitle = "Turn On";
      }
      this.title = "Are you sure you want to ";
      this.activeModal = true;
    },
    async update() {
      this.sending = true;
      if (this.authUser.twoFactor == "On") {
        this.data.status = "Off";
      } else {
        this.data.status = "On";
      }
      const res = await this.callApi(
        "post",
        "/api/update_two_factor",
        this.data
      );
      if (res.status == 200) {
        this.authUser.twoFactor = this.data.status;
        if (this.authUser.twoFactor == "On") {
          this.instance("success", "Turned On");
        } else {
          this.instance("error", "Turned Off");
        }
      } else {
        this.swr();
      }
      this.sending = false;
      this.activeModal = false;
    },
  },
  created() {},
};
</script>
