<template>
  <div class="connection--item mt-40">
    <h5 class="post-title">Account settings</h5>
    <ul>
      <li>
        <div class="content">
          <div class="content--image">
            <img :src="authUser.image" />
          </div>
          <div>
            <h4>{{ authUser.name }}</h4>
            <p>{{ authUser.email }}</p>
          </div>
        </div>

        <button class="d-none d-md-block btn btn__border">
          <i class="fa-solid fa-pencil"></i>
          Edit
        </button>
      </li>
      <li>
        <div class="content">
          <div>
            <h4 class="mb-2">Password</h4>
            <p class="mb-2">
              We suggest you use a password you don't use anywhere else to help
              keep your account secure.
            </p>
            <nuxt-link to="/settings/change_password" class="btn btn__border"
              >Change Password</nuxt-link
            >
          </div>
        </div>
      </li>
      <li>
        <div class="content">
          <div>
            <h4 class="mb-2">Delete your account</h4>
            <p class="mb-2">Are you sure you want to delete your account?</p>
            <p class="mb-2">
              When you delete your account, you won't be able to retrieve the
              content or information you've shared on LURC. Everything will be
              deleted.
            </p>

            <button class="btn btn__border" @click="showDeleteModal">
              <i class="fa-solid fa-trash"></i>
              Continue to account deletion
            </button>
          </div>
        </div>
      </li>
    </ul>
    <Modal v-model="deleteModal" width="360">
      <p slot="header" style="color: #566d7e; text-align: center">
        <Icon type="close"></Icon>
        <span>Delete Account</span>
      </p>
      <div>
        <div style="margin-bottom: 20px">
          Are you sure you want to delete your account?
        </div>
        <div>
          <Form label-position="top">
            <FormItem
              label="Please Enter Your Password"
              :error="data.passwordError"
            >
              <Input
                type="password"
                v-model="data.password"
                placeholder="Password"
              ></Input>
            </FormItem>
          </Form>
        </div>
      </div>
      <div slot="footer">
        <Button
          style="color: #566d7e"
          size="large"
          long
          @click="remove"
          :disabled="isLoading"
          :loading="isLoading"
          >{{ isLoading ? "Deleting..." : "Delete" }}</Button
        >
      </div>
    </Modal>
  </div>
</template>

<script>
export default {
  middleware: "auth",

  components: {},
  data() {
    return {
      deleteModal: false,
      isLoading: false,

      data: {
        password: "",
        passwordError: "",
      },
    };
  },
  computed: {},
  methods: {
    showDeleteModal() {
      this.data.password = "";
      this.data.passwordError = "";
      this.deleteModal = true;
    },
    async remove() {
      this.isLoading = true;
      this.data.passwordError = "";
      const res = await this.callApi("post", "/api/delete_account", this.data);
      if (res.status == 201) {
        this.$store.commit("setAuthInfo", false);
        this.setCookie("token", null);
        this.$router.push(`/`);

        this.s(res.data.msg);
      } else if (res.status == 422) {
        this.data.passwordError = res.data.message;
        if (res.data.password) {
          this.data.passwordError = res.data.password[0];
        }
      } else {
        this.deleteModal = false;
        this.e("Oops!", "Something went wrong, please try again!");
      }
      this.isLoading = false;
    },
  },
  async created() {},
  mounted() {},
};
</script>

<style></style>
