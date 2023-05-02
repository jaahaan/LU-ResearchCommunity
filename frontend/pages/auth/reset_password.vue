<template>
  <div class="login-section">
    <div class="left">
      <img :src="'/assets/images/lurc.png'" alt="img" />
    </div>

    <div class="right">
      <div class="form">
        <h1>Reset Password</h1>
        <div class="mb-2">
          Email Address
          <Input
            type="email"
            v-model="data.email"
            disabled
            placeholder="Email Address"
          />
          <span class="text-danger" v-if="errors.email">{{
            errors.email
          }}</span>
        </div>
        <div class="mb-2">
          Enter New Password
          <Input
            type="password"
            v-model="data.password"
            placeholder="Enter New Password"
          />
          <span class="w-full text-danger" v-if="errors.password"
            >{{ errors.password }}
          </span>
        </div>

        <div class="mb-2">
          Confirm New Password
          <Input
            type="password"
            v-model="data.password_confirmation"
            placeholder="Confirm New Password"
          />
          <span class="w-full text-danger" v-if="errors.password_confirmation"
            >{{ errors.password_confirmation }}
          </span>
        </div>

        <div class="mb-2">
          <button
            :class="[
              data.email && data.password
                ? ' main-btn-change col-12'
                : ' main-btn col-12',
              ' main-btn col-12',
            ]"
            @click="submit"
            :disabled="isSubmitting"
            :loading="isSubmitting"
          >
            {{ isSubmitting ? "Submitting..." : "Reset Password" }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters } from "vuex";

export default {
  middleware: "guest",
  data() {
    return {
      data: {
        email: "",
        password: "",
        password_confirmation: "",
        otp: "",
      },
      isSubmitting: false,
      errors: [],
    };
  },

  computed: {
    ...mapGetters({
      passwordReset: "passwordReset",
    }),
  },

  //All of its synchronous child components have been mounted (does not include async components or components inside <Suspense> trees).
  mounted() {
    this.data.email = this.passwordReset.email;
    this.data.otp = this.passwordReset.otp;
  },

  methods: {
    async submit() {
      // if (this.data.email.trim() == "") return this.e("Email is required");
      // if (this.data.password.trim() == "")
      //   return this.e("Password is required");
      // if (this.data.password_confirmation.trim() == "")
      //   return this.e("Confirm Password is required");

      this.isSubmitting = true;
      const res = await this.callApi("post", "/api/reset_password", this.data);

      if (res.status == 200) {
        this.s(res.data.msg);
        this.$router.push("/login");
        this.data.email = "";
        this.data.password = "";
        this.data.password_confirmation = "";
      } else {
        if (res.status == 401) {
          this.e(res.data.msg);
        } else if (res.status == 422) {
          if (res.data.email) {
            this.errors.email = res.data.email[0];
          }
          if (res.data.password) {
            this.errors.password = res.data.password[0];
          }
          if (res.data.password_confirmation) {
            this.errors.password_confirmation =
              res.data.password_confirmation[0];
          }
        } else {
          this.swr();
        }
      }
      this.isSubmitting = false;
    },
  },
};
</script>
