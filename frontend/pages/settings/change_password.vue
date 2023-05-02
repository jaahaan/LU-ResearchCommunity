<template>
  <div class="login-section mt-40 b-radius">
    <div class="right">
      <div class="form">
        <h1>Change Password</h1>
        <form autocomplete="off">
          <div class="mb-2">
            Old Password
            <div class="password">
              <Input
                :type="passwordFieldTypeO"
                v-model="data.old_password"
                placeholder="Old Password"
              />
              <div class="icon">
                <i
                  @click="toggleShowOld"
                  class="fas"
                  :class="{
                    'fa-eye-slash': !showOldPassword,
                    'fa-eye': showOldPassword,
                  }"
                ></i>
              </div>
            </div>
            <span class="text-danger" v-if="errors.old_password">{{
              errors.old_password
            }}</span>
            <span class="text-danger" v-if="errmsg">{{ errmsg }}</span>
          </div>
          <div class="mb-2">
            New Password
            <div class="password">
              <Input
                :type="passwordFieldTypeN"
                placeholder="New Password"
                v-model="data.password"
              />
              <div class="icon">
                <i
                  @click="toggleShowNew"
                  class="fas"
                  :class="{
                    'fa-eye-slash': !showNewPassword,
                    'fa-eye': showNewPassword,
                  }"
                ></i>
              </div>
            </div>
            <span class="text-danger" v-if="errors.password">{{
              errors.password
            }}</span>
          </div>
          <div class="mb-2">
            Confirm New Password
            <div class="password">
              <Input
                :type="passwordFieldTypeCN"
                placeholder="Confirm New Password"
                v-model="data.password_confirmation"
              />
              <div class="icon">
                <i
                  @click="toggleShowConNew"
                  class="fas"
                  :class="{
                    'fa-eye-slash': !showConfirmNewPassword,
                    'fa-eye': showConfirmNewPassword,
                  }"
                ></i>
              </div>
            </div>
            <span class="text-danger" v-if="errors.password_confirmation">{{
              errors.password_confirmation
            }}</span>
          </div>
          <div class="mb-2">
            <button
              type="button"
              :class="[
                data.old_password && data.password && data.password_confirmation
                  ? ' main-btn-change col-12'
                  : ' main-btn col-12',
                ' main-btn  col-12',
              ]"
              @click="updatePass"
            >
              {{ isAdding ? "Saving.." : "Save" }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters } from "vuex";

export default {
  middleware: "auth",

  data() {
    return {
      data: {
        msg: "",
        old_password: "",
        password: "",
        password_confirmation: "",
      },
      isAdding: false,
      errors: [],
      errmsg: "",
      showOldPassword: false,
      showNewPassword: false,
      showConfirmNewPassword: false,
      passwordFieldTypeO: "password",
      passwordFieldTypeN: "password",
      passwordFieldTypeCN: "password",
    };
  },
  // computed: {
  //   buttonLabel() {
  //     return this.showPassword ? "Hide" : "Show";
  //   },
  // },

  methods: {
    toggleShowOld() {
      this.showOldPassword = !this.showOldPassword;
      this.passwordFieldTypeO =
        this.passwordFieldTypeO === "password" ? "text" : "password";
    },
    toggleShowNew() {
      this.showNewPassword = !this.showNewPassword;
      this.passwordFieldTypeN =
        this.passwordFieldTypeN === "password" ? "text" : "password";
    },
    toggleShowConNew() {
      this.showConfirmNewPassword = !this.showConfirmNewPassword;
      this.passwordFieldTypeCN =
        this.passwordFieldTypeCN === "password" ? "text" : "password";
    },
    async updatePass() {
      // if (this.data.old_password.trim() == "")
      //   return this.e("Old Password is required");
      // if (this.data.password.trim() == "")
      //   return this.e("New Password is required");
      // if (this.data.password_confirmation.trim() == "")
      //   return this.e("Confirm New Password is required");
      // if (this.data.password.trim() !== this.data.password_confirmation.trim())
      //   return this.e("Password Mismatch!!");
      this.errors = [];
      this.isAdding = true;
      const res = await this.callApi("post", "/api/update_pass", this.data);
      if (res.status == 201) {
        this.data.old_password = "";
        this.data.password = "";
        this.data.password_confirmation = "";

        this.instance("success", res.data.msg);
      } else {
        if (res.status == 422) {
          this.errmsg = "";
          if (res.data.old_password) {
            this.errors.old_password = res.data.old_password[0];
            // this.e(res.data.email[0]);
          }
          if (res.data.password) {
            this.errors.password = res.data.password[0];
          }
          if (res.data.password_confirmation) {
            this.errors.password_confirmation =
              res.data.password_confirmation[0];
          }
          // for (let i in res.data.errors) {
          //   this.errors = res.data.errors;
          //   console.log(this.errors);
          //   // this.e(res.data.errors[i][0]);
          // }
        } else if (res.status == 401) {
          this.errmsg = res.data.msg;
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
    },
  },
};
</script>
