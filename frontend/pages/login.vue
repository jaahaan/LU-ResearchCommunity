<template>
  <div class="login-section">
    <div class="left">
      <img :src="'/assets/images/lurc.png'" alt="img" />
    </div>
    <!-- Login Form -->
    <div class="right" v-if="isLoggingBlock">
      <div class="form">
        <h1>Login</h1>

        <div class="mb-2">
          Email
          <input type="email" v-model="data.email" placeholder="Email" />
          <span class="text-danger" v-if="errors.email">{{
            errors.email
          }}</span>
        </div>

        <div class="mb-2">
          Password
          <div class="password">
            <input
              :type="passwordFieldType"
              v-model="data.password"
              placeholder="Password"
            />
            <div class="icon">
              <i
                @click="toggleShow"
                class="fas"
                :class="{
                  'fa-eye-slash': !showPassword,
                  'fa-eye': showPassword,
                }"
              ></i>
            </div>
          </div>
          <div class="d-block">
            <span class="w-full text-danger float-start" v-if="errors.password"
              >{{ errors.password }}
            </span>

            <nuxt-link class="float-end" to="/auth/forgot_password"
              >Forgot Password</nuxt-link
            >
          </div>
        </div>

        <div class="mb-2">
          <button
            type="button"
            :class="[
              data.email && data.password
                ? ' main-btn-change col-12'
                : ' main-btn col-12',
              ' main-btn  col-12',
            ]"
            @click="login"
          >
            {{ isLogging ? "Logging In.." : "Login" }}
          </button>
        </div>
      </div>
    </div>

    <!-- Two Factor Form -->
    <div class="right" v-else-if="!isLoggingBlock">
      <div class="form">
        <h1>Two Factor Authentication</h1>
        <div class="alert alert-dark" v-if="msg">
          {{ msg }}
        </div>
        <div class="time-card">
          <div v-if="countdownActive">
            <h3>OTP will expire in</h3>
            <ul class="time-card__counter">
              <li>
                <span>{{ minutes }}</span
                >MIN
              </li>
              <li>
                <span>{{ seconds }}</span
                >SEC
              </li>
            </ul>
          </div>
          <div v-else>
            <h3>OTP expired</h3>
          </div>
        </div>
        <div class="mb-2">
          <h1>Enter OTP</h1>
          <div class="otp-input">
            <input
              v-for="(digit, index) in digits"
              :key="index"
              v-model="digit.value"
              type="text"
              pattern="[0-9]*"
              inputmode="numeric"
              maxlength="1"
              @input="handleInput(index, $event)"
              ref="otpDigits"
            />
          </div>
          <div class="text-center">
            <span class="text-danger" v-if="errors.otp">{{ errors.otp }}</span>
          </div>
          <span class="text-danger" v-if="errmsg">{{ errmsg }}</span>
        </div>
        <a class="float-end mb-2 d-flex align-items-center" @click="resendOTP">
          {{ isResending ? "Re-sending OTP  " : "Re-send OTP  " }}
          <i
            class="ivu-load-loop ivu-icon ivu-icon-ios-loading"
            v-if="isResending"
          ></i>
          <i class="fa-solid fa-circle-check" v-if="reSent"></i>
        </a>
        <div class="mb-2">
          <button
            :class="[
              data.otp ? 'main-btn-change col-12' : 'main-btn col-12',
              ' main-btn col-12',
            ]"
            @click="submit"
            :disabled="isSubmitting"
            :loading="isSubmitting"
          >
            {{ isSubmitting ? "Submitting..." : "Submit OTP" }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "login",
  middleware: "guest",
  //local storage
  data() {
    return {
      data: {
        email: "",
        password: "",
        otp: "",
      },

      msg: null,
      errmsg: null,
      isLoggingBlock: true,
      isLogging: false,
      isSubmitting: false,
      isResending: false,
      reSent: false,
      errors: [],
      props: ["msg"],
      showPassword: false,
      passwordFieldType: "password",
      time: 0,
      countdownActive: false,
      countdown: null,
      digits: [
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
      ],
      in: [],
    };
  },
  computed: {
    minutes() {
      const minutes = Math.floor(this.time / 60)
        .toString()
        .padStart(2, "0");
      return `${minutes}`;
    },
    seconds() {
      const seconds = (this.time % 60).toString().padStart(2, "0");

      return `${seconds}`;
    },
  },
  methods: {
    toggleShow() {
      this.showPassword = !this.showPassword;
      this.passwordFieldType =
        this.passwordFieldType === "password" ? "text" : "password";
    },
    handleInput(index, event) {
      const { value } = event.target;
      this.in.push(value);
      if (this.in.length === 6) {
        this.submit();
      } else {
        if (value.length > 0) {
          this.focusNext(index);
        } else {
          this.in.splice(index, 1);
          console.log(this.in.length);
          this.focusPrevious(index);
        }
      }

      // else if (this.digits.length === 6) {
      //   this.submit();
      // }
    },
    focusNext(index) {
      if (index < this.digits.length - 1) {
        this.$refs.otpDigits[index + 1].focus();
      } else {
        this.$refs.otpDigits[index].blur();
      }
    },
    focusPrevious(index) {
      if (index > 0) {
        this.$refs.otpDigits[index - 1].focus();
      }
    },
    async showRemaining() {
      this.countdownActive = true;
      this.countdown = setInterval(() => {
        this.time--;
        if (this.time === 0) {
          this.stopCountdown();
        }
      }, 1000);
    },
    // Stop the countdown
    stopCountdown() {
      this.countdownActive = false;
      clearInterval(this.countdown);
    },
    // Reset the countdown
    resetCountdown() {
      this.time = 0;
      this.stopCountdown();
    },
    //The keyword async before a function makes the function return a promise:
    async login() {
      // if (this.data.email.trim() == "")
      //     return this.e("Email is required");
      // if (this.data.password.trim() == "")
      //     return this.e("Password is required");
      this.isLogging = true;
      this.errors = [];

      //The await keyword makes the function pause the execution and wait for a resolved promise before it continues:
      const res = await this.callApi("post", "/api/login", this.data);

      if (res.status == 200) {
        console.log(res.data.user);
        console.log(res.data.token);

        this.$store.dispatch("setAuthInfo", res.data.user);
        this.$store.dispatch("setToken", res.data.token);
        this.setCookie("token", res.data.token);
        // this.$router.push(`/home`);
        this.$router.go(`/home`);

        this.s("You are logged In");

        // if (this.$route.query.callback)
        //   return this.$router.push(this.$route.query.callback);
        // window.location = "/";
      } else if (res.status == 201) {
        this.msg = res.data.msg;
        this.time = res.data.data;
        this.isLoggingBlock = false;
        this.showRemaining();
      } else {
        if (res.status == 400) {
          // this.msg = res.data.msg;
          this.e(res.data.error);
        } else if (res.status == 401) {
          this.errors.password = res.data.msg;
          // this.e(res.data.msg);
        } else if (res.status == 422) {
          if (res.data.email) {
            this.errors.email = res.data.email[0];
          }
          if (res.data.password) {
            this.errors.password = res.data.password[0];
          }
        } else if (res.status == 402) {
          let emailPassword = {
            email: this.data.email,
            password: this.data.password,
          };
          this.$store.commit("setUnauthorizedCredential", emailPassword);
          this.e(res.data.msg);
          this.$router.push(`/auth/account-activation`);
        } else {
          this.swr();
        }
      }
      this.isLogging = false;
    },

    async submit() {
      this.digits.forEach((input) => {
        this.data.otp = this.data.otp + input.value;
      });
      this.isSubmitting = true;
      const res = await this.callApi(
        "post",
        "/api/submit_twoFactor_otp",
        this.data
      );

      if (res.status == 200) {
        this.$store.dispatch("setAuthInfo", res.data.user);
        this.$store.dispatch("setToken", res.data.token);
        this.setCookie("token", res.data.token);
        // window.location = "/home";
        this.$router.push("/home");
        this.s("You are logged In");
        this.digits = [
          { value: "" },
          { value: "" },
          { value: "" },
          { value: "" },
          { value: "" },
          { value: "" },
        ];
      } else {
        if (res.status == 401) {
          this.errors.otp = res.data.msg;
        } else if (res.status == 402) {
          this.errors.otp = res.data.msg;
          this.msg = res.data.msg;
          this.time = res.data.data;
          this.isLoggingBlock = false;
          this.showRemaining();
        } else if (res.status == 422) {
          if (res.data.otp) {
            this.errors.otp = res.data.otp[0];
          }
          if (res.data.email) {
            // this.errors.email = res.data.email[0];
            this.e(res.data.email[0]);
          }
          if (res.data.password) {
            // this.errors.password = res.data.password[0];
            this.e(res.data.password[0]);
          }
        } else {
          this.swr();
        }
      }
      this.data.otp = "";
      this.isSubmitting = false;
    },
    async resendOTP() {
      this.errors = [];
      this.data.otp = "";
      this.reSent = false;

      this.isResending = true;
      const res = await this.callApi("post", "/api/resend_otp", this.data);
      this.msg = "";
      this.digits = [
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
      ];
      this.data.otp = "";
      if (res.status == 201) {
        this.reSent = true;
        this.resetCountdown();
        this.showRemaining();
        this.msg = res.data.msg;
      } else if (res.status == 422) {
        if (res.data.email) {
          // this.e(res.data.email[0]);
          this.msg = res.data.email[0];
        } else if (res.data.password) {
          // this.errors.password = res.data.password[0];
          this.msg = res.data.password[0];
        }
      } else {
        this.swr();
      }

      this.isResending = false;
    },
  },

  // created(){
  //     if(this.authInfo) this.$router.push('/')
  // }
};
</script>
<style scoped>
input {
  display: block;
  padding: 6px 15px;
  width: 100%;
  box-sizing: none;
  border: 1px solid #fff;
  border-radius: 5px;
  color: #555;
}
</style>
