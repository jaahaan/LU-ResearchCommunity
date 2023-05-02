<template>
  <div class="login-section">
    <div class="left">
      <img :src="'/assets/images/lurc.png'" alt="img" />
    </div>

    <!-- Login Form -->
    <div class="right">
      <div class="form">
        <h1>Forgot Password!!</h1>
        <div class="alert alert-dark">
          <p>
            Enter your email address and we will send an OTP to reset your
            password.
          </p>
        </div>

        <div class="mb-2">
          Email Address
          <input
            type="email"
            class="form-control"
            v-model="data.email"
            placeholder="Email Address"
          />
          <span class="text-danger" v-if="errors.email">{{
            errors.email
          }}</span>
        </div>

        <div class="mb-2">
          <button
            :class="[
              data.email ? ' main-btn-change col-12' : ' main-btn col-12',
              ' main-btn col-12',
            ]"
            @click="send"
            :disabled="isSending"
            :loading="isSending"
          >
            {{ isSending ? "Sending OTP..." : "Send OTP" }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  middleware: "guest",
  data() {
    return {
      data: {
        email: "",
      },
      isSending: false,
      errors: [],
    };
  },
  methods: {
    async send() {
      // if (this.data.email.trim() == "")
      //     return this.e("Email is required");
      this.isSending = true;
      const res = await this.callApi(
        "post",
        "/api/send_reset_password_otp",
        this.data
      );

      if (res.status == 200) {
        this.s(res.data.msg);
        this.$router.push(`/auth/otp?email=${this.data.email}`);
      } else {
        if (res.status == 401) {
          this.e(res.data.msg);
        } else if (res.status == 422) {
          if (res.data.email) {
            this.errors.email = res.data.email[0];
          }
        } else {
          this.swr();
        }
      }
      this.isSending = false;
    },
  },
};
</script>
