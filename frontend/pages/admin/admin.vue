<template>
  <div class="connection--item mt-40">
    <div class="banner">
      <h5 class="post-title">
        Admins<a class="main-btn float-end" @click="showAdminModal">
          Add Admin
        </a>
      </h5>

      <Form ref="formInline">
        <FormItem prop="user">
          <Input
            type="text"
            v-model="search"
            placeholder="Search"
            @on-keyup="getAllAdmins"
          >
            <Icon type="ios-search" slot="prepend"></Icon>
          </Input>
        </FormItem>
      </Form>
      <div v-if="loading" class="loader-lg">
        <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
      </div>
      <div v-else>
        <ul>
          <li v-for="(item, index) in adminList">
            <div class="content">
              <div class="content--image">
                <img :src="item.image" />
              </div>
              <div>
                <nuxt-link :to="`/profile/${item.user_slug}/overview`"
                  ><h4>{{ item.name }}</h4>
                </nuxt-link>
                <p>{{ item.email }}</p>
                <div>
                  <span>{{ item.designation }}</span>

                  <span class="dot">•</span>
                  <span>{{ item.department.department_name }}</span>
                </div>
              </div>
            </div>
            <button
              class="tf tf__success"
              v-if="item.email == 'lisa_cse@lus.ac.bd'"
            >
              Super Admin
            </button>
            <button class="can" @click="showRemove(index)" v-else>
              <i class="lni lni-trash-can"></i>
            </button>
          </li>
        </ul>

        <Modal v-model="addAdminModal" :closable="true">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>Add Admin</div>
            </h5>
            <div class="mb-2">
              <Select
                v-model="data.user_name"
                placeholder="Select User Name"
                filterable
                clearable
                :remote-method="getAllUsers"
                :loading="isUserLoading"
              >
                <Option
                  v-for="(item, i) in userList"
                  :value="item.id"
                  :key="i"
                  >{{ item.name }}</Option
                >
              </Select>
              <span class="text-danger" v-if="errors.user_name">{{
                errors.user_name
              }}</span>
            </div>
          </div>
          <div slot="footer">
            <div>
              <Button
                class="main-btn main-btn__bg"
                @click="addAdmin"
                :disabled="adding"
                :loading="adding"
                >{{ adding ? "Adding.." : "Add" }}</Button
              >
            </div>
          </div>
        </Modal>

        <Modal v-model="deleteModal" width="360">
          <p slot="header" style="color: #566d7e; text-align: center">
            <Icon type="close"></Icon>
            <span> Remove {{ UpdateValue.name }} from admin</span>
          </p>
          <div>
            <div style="margin-bottom: 20px">
              Are you sure you want remove {{ UpdateValue.name }}
            </div>
            <div>
              <Form label-position="top">
                <FormItem
                  label="Please Enter Your Password"
                  :error="UpdateValue.passwordError"
                >
                  <Input
                    type="password"
                    v-model="UpdateValue.password"
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
              :disabled="sending"
              :loading="sending"
              >{{ sending ? "Removing..." : "Delete" }}</Button
            >
          </div>
        </Modal>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      search: "",
      loading: false,

      deleteModal: false,
      addAdminModal: false,
      isUserLoading: false,
      adding: false,

      sending: false,
      data: {
        user_name: "",
      },
      UpdateValue: {
        indexNumber: null,
        id: null,
        name: "",
        password: "",
        passwordError: "",
      },

      userList: [],
      adminList: [],
      errors: [],
    };
  },

  methods: {
    showAdminModal() {
      this.errors = [];
      this.data.user_name = "";
      this.addAdminModal = true;
    },
    async addAdmin() {
      this.errors = [];
      this.adding = true;
      const res = await this.callApi("post", `/api/add_admin`, this.data);
      if (res.status == 200) {
        this.s_msg("Admin Added");
        this.getAllAdmins();
        this.data.user_name = "";
        this.addAdminModal = false;
      } else if (res.status == 422) {
        if (res.data.user_name) {
          this.errors.user_name = res.data.user_name[0];
        }
      } else {
        this.swr();
      }
      this.adding = false;
    },

    showRemove(index) {
      this.UpdateValue.id = this.adminList[index].id;
      this.UpdateValue.name = this.adminList[index].name;
      this.UpdateValue.indexNumber = index;
      this.deleteModal = true;
    },

    async remove() {
      this.UpdateValue.passwordError = "";
      if (
        this.UpdateValue.password == "" ||
        this.UpdateValue.password.trim() == ""
      ) {
        this.UpdateValue.passwordError = "Password is required";
        return;
      }
      this.sending = true;
      let ob = {
        id: this.UpdateValue.id,
        password: this.UpdateValue.password,
      };
      const res = await this.callApi("post", `/api/admin_remove`, ob);
      if (res.status == 200) {
        this.adminList.splice(this.UpdateValue.indexNumber, 1);
        this.s_msg("Removed Successfully!");
        this.deleteModal = false;
        this.UpdateValue = {
          id: "",
          indexNumber: null,
          password: "",
          passwordError: "",
        };
      } else if (res.status == 422) {
        this.UpdateValue.passwordError = res.data.message;
      } else {
        this.deleteModal = false;
        this.e("Oops!", "Something went wrong, please try again!");
      }
      this.sending = false;
    },

    async getAllAdmins() {
      this.loading = true;
      const res = await this.callApi(
        "get",
        `/api/adminList?search=${this.search}`
      );
      if (res.status == 200) {
        this.adminList = res.data.data;
      } else {
        this.swr();
      }
      this.loading = false;
    },

    async getAllUsers(query) {
      this.isUserLoading = true;
      const res = await this.callApi("get", `/api/userList?search=${query}`);
      if (res.status == 200) {
        this.userList = res.data.data;
      } else {
        this.swr();
      }
      this.isUserLoading = false;
    },
  },
  async created() {
    await this.getAllAdmins();
  },
};
</script>
