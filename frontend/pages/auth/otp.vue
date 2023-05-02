<template>
  <div class="login-section">
    <div class="left">
      <img :src="'/assets/images/lurc.png'" alt="img" />
    </div>

    <div class="right">
      <div class="form">
        <div class="alert alert-dark text-center">
          <p>We have sent an OTP to your email.</p>
        </div>

        <div class="time-card">
          <i
            class="ivu-load-loop ivu-icon ivu-icon-ios-loading loader-sm"
            v-if="isLoading"
          ></i>
          <div v-else-if="countdownActive">
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
              data.otp ? ' main-btn-change col-12' : ' main-btn col-12',
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
  middleware: "guest",

  data() {
    return {
      digits: [
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
      ],
      data: {
        email: "",
        otp: "",
      },
      isLoading: true,

      isSubmitting: false,
      isResending: false,
      reSent: false,
      errors: [],
      msg: "",
      otpExp: "",
      isSubmitting: false,
      displayMin: 0,
      displaySec: 0,
      isOtp: false,
      time: 0, // Time in seconds
      countdownActive: false, // Indicates if the countdown is active or not
      countdown: null, // Reference to the setInterval function
      in: [],
    };
  },
  computed: {
    // Format time as string (HH:mm:ss)

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
      this.isLoading = true;
      const res = await this.callApi("post", "/api/get_otp_time", this.data);

      if (res.status == 200) {
        this.time = res.data.data;
        this.countdownActive = true;
        this.countdown = setInterval(() => {
          this.time--;
          if (this.time === 0) {
            this.stopCountdown();
          }
        }, 1000);
      }
      this.isLoading = false;
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

    async submit() {
      // if (this.data.otp.trim() == "") return this.e("OTP is required");
      // var arr = this.digits.join().toString();
      this.digits.forEach((input) => {
        this.data.otp = this.data.otp + input.value;
      });

      console.log("otp");

      console.log(this.data.otp);

      this.isSubmitting = true;
      const res = await this.callApi(
        "post",
        "/api/submit_reset_password_otp",
        this.data
      );

      if (res.status == 200) {
        this.s(res.data.msg);
        this.$store.commit("setPasswordReset", this.data);
        this.$router.push("/auth/reset_password");
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
          this.data.otp = "";
          // this.$router.push("/auth/forgot_password");
        } else if (res.status == 422) {
          if (res.data.otp) {
            this.errors.otp = res.data.otp[0];
          }
        } else {
          this.e(res.data.msg);
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
      const res = await this.callApi(
        "post",
        "/api/resend_pass_reset_otp",
        this.data
      );
      this.msg = "";

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
      this.digits = [
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
        { value: "" },
      ];
      this.data.otp = "";
      this.isResending = false;
    },
  },
  async created() {
    console.log(this.$route.query.email);
    this.data.email = this.$route.query.email;
    this.showRemaining();
  },
};
</script>
