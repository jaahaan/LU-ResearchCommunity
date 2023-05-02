<template>
  <div>
    <!-- <h1 class="text-center mb-3">Register As Teacher</h1> -->
    <div class="mb-2">
      <input type="text" v-model="data.name" placeholder="Name" />
      <span class="text-danger" v-if="errors.name">{{ errors.name }}</span>
    </div>
    <div class="mb-2">
      <input type="email" v-model="data.email" placeholder="Email" />
      <span class="text-danger" v-if="errors.email">{{ errors.email }}</span>
    </div>
    <form autocomplete="off">
      <div class="mb-2">
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
        <span class="text-danger" v-if="errors.password">{{
          errors.password
        }}</span>
      </div>
      <div class="mb-2">
        <div class="password">
          <input
            :type="conPasswordFieldType"
            v-model="data.password_confirmation"
            placeholder="Confirm Password"
          />
          <div class="icon">
            <i
              @click="toggleConPassShow"
              class="fas"
              :class="{
                'fa-eye-slash': !showConPassword,
                'fa-eye': showConPassword,
              }"
            ></i>
          </div>
        </div>
        <span class="text-danger" v-if="errors.password_confirmation">{{
          errors.password_confirmation
        }}</span>
      </div>
      <div class="mb-2">
        <Select v-model="data.designation" placeholder="Designation">
          <Option value="Head">Head</Option>
          <Option value="Professor">Professor</Option>
          <Option value="Associate Professor">Associate Professor</Option>
          <Option value="Assistant Professor">Assistant Professor</Option>
          <Option value="Lecturer">Lecturer</Option>
        </Select>
        <span class="text-danger" v-if="errors.designation">{{
          errors.designation
        }}</span>
      </div>
      <div class="mb-2">
        <Select v-model="data.department" placeholder="Department">
          <Option
            v-for="(department, index) in departmentInfo"
            :key="index"
            :value="department.id"
            >{{ department.department_name }}</Option
          >
        </Select>
        <span class="text-danger" v-if="errors.department">{{
          errors.department
        }}</span>
      </div>
      <div class="mb-2">
        <button
          type="button"
          :class="[
            data.name &&
            data.email &&
            data.password &&
            data.password_confirmation &&
            data.designation &&
            data.department
              ? ' main-btn-change col-12'
              : ' main-btn col-12',
            ' main-btn col-12',
          ]"
          @click="register"
        >
          {{ isLoading ? "Registering..." : "Register" }}
        </button>
      </div>
    </form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      data: {
        name: "",
        email: "",
        password: "",
        password_confirmation: "",
        designation: "",
        department: "",
      },
      isLoading: false,
      errors: [],
      showPassword: false,
      showConPassword: false,
      passwordFieldType: "password",
      conPasswordFieldType: "password",
    };
  },
  methods: {
    toggleShow() {
      this.showPassword = !this.showPassword;
      this.passwordFieldType =
        this.passwordFieldType === "password" ? "text" : "password";
    },
    toggleConPassShow() {
      this.showConPassword = !this.showConPassword;
      this.conPasswordFieldType =
        this.conPasswordFieldType === "password" ? "text" : "password";
    },
    async register() {
      // if (this.data.name.trim() == "") return this.e("Name is required");
      // if (this.data.email.trim() == "")
      //     return this.e("Email is required");
      // if (this.data.password.trim() == "")
      //     return this.e("Password is required");
      // if (this.data.password_confirmation.trim() == "")
      //     return this.e("Confirm Password is required");
      // if (
      //     this.data.password.trim() !==
      //     this.data.password_confirmation.trim()
      // )
      //     return this.e("Password Mismatch!!");
      // if (this.data.designation.trim() == "")
      //     return this.e("Designation is required");
      // if (this.data.department.trim() == "")
      //     return this.e("Department is required");
      this.isLoading = true;

      const res = await this.callApi("post", "/api/register_t", this.data);

      if (res.status === 201) {
        let emailPassword = {
          email: this.data.email,
          password: this.data.password,
        };
        this.$store.commit("setUnauthorizedCredential", emailPassword);
        this.$router.push(`/auth/account-activation`);
        this.s(res.data.msg);
        this.data.name = "";
        this.data.email = "";
        this.data.password = "";
        this.data.password_confirmation = "";
        this.data.designation = "";
        this.data.department = "";
        this.errors = [];
      } else {
        if (res.status == 422) {
          if (res.data.name) {
            this.errors.name = res.data.name[0];
          }
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
          if (res.data.designation) {
            this.errors.designation = res.data.designation[0];
          }
          if (res.data.department) {
            this.errors.department = res.data.department[0];
          }
          // for (let i in res.data.errors) {
          //   this.errors = res.data.errors;
          //   console.log(this.errors);
          //   // this.e(res.data.errors[i][0]);
          // }
        } else {
          this.swr();
        }
      }
      this.isLoading = false;
    },
  },
  async created() {},
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
