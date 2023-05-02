<template>
  <div>
    <div v-if="isDataLoading == false">
      <section class="container">
        <div class="teacher-section">
          <div class="teacher-section--table">
            <div class="d-block pt-5 pb-5">
              <h4 class="float-start">Faculty Members</h4>
              <button class="main-btn float-end" @click="addTeacherButton">
                Add New Member
              </button>
            </div>
            <Form ref="formInline">
              <FormItem prop="user">
                <Input
                  type="text"
                  v-model="search"
                  placeholder="Search Faculty Member"
                  @on-keyup="filterTeachers"
                >
                  <Icon type="ios-search" slot="prepend"></Icon>
                </Input>
              </FormItem>
            </Form>
            <table class="table table-bordered">
              <thead>
                <tr>
                  <th scope="col">Email</th>
                  <th scope="col">Designation</th>
                  <th scope="col">Department</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(teacher, index) in teachersInfo" :key="index">
                  <template v-if="editObj.id == teacher.id">
                    <td>
                      <input
                        type="email"
                        v-model="editObj.email"
                        placeholder="Email"
                        :ref="`teacher${teacher.id}`"
                      />
                      <span class="text-danger" v-if="errors.email">{{
                        errors.email[0]
                      }}</span>
                    </td>
                    <td>
                      <Select
                        v-model="editObj.designation"
                        placeholder="Designation"
                      >
                        <Option value="Head">Head</Option>
                        <Option value="Professor">Professor</Option>
                        <Option value="Associate Professor"
                          >Associate Professor</Option
                        >
                        <Option value="Assistant Professor"
                          >Assistant Professor</Option
                        >
                        <Option value="Lecturer">Lecturer</Option>
                      </Select>
                      <span class="text-danger" v-if="errors.designation">{{
                        errors.designation[0]
                      }}</span>
                    </td>
                    <td>
                      <Select
                        v-model="editObj.department"
                        placeholder="Department"
                      >
                        <Option value="CSE">CSE</Option>
                        <Option value="EEE">EEE</Option>
                        <Option value="ARCH">ARCH</Option>
                        <Option value="CE">CE</Option>
                        <Option value="BuA">BuA</Option>
                        <Option value="ENG">ENG</Option>
                      </Select>
                      <span class="text-danger" v-if="errors.department">{{
                        errors.department[0]
                      }}</span>
                    </td>
                    <td class="text-center">
                      <i
                        class="fa-solid fa-square-check"
                        @click="updateTeacher()"
                      ></i>
                      <i class="fa-solid fa-xmark" @click="reset()"></i>
                    </td>
                  </template>
                  <template v-else>
                    <td>{{ teacher.email }}</td>
                    <td>{{ teacher.designation }}</td>
                    <td>{{ teacher.department }}</td>
                    <td>
                      <i
                        class="fa-solid fa-pen-to-square"
                        @click="showEdit(index)"
                      ></i>
                      <i
                        class="lni lni-trash-can"
                        @click="showRemove(index)"
                      ></i>
                    </td>
                  </template>
                </tr>
                <div
                  v-if="loadMoreLoading && !noTeacherRemaining"
                  class="loader-lg"
                >
                  <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
                </div>
              </tbody>
            </table>
            <!-- <table class="table table-bordered">
              <thead>
                <tr>
                  <th scope="col"></th>
                  <th scope="col"></th>
                  <th scope="col"></th>
                  <th scope="col"></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
              </tbody>
            </table> -->
          </div>
        </div>
      </section>

      <Modal v-model="addTeacherModal" :closable="false">
        <div class="research-post--item" id="modal">
          <h5 class="post-title">
            <div>Add New Faculty Member</div>
            <div class="btn-edit text-danger" @click="closeModal">
              <i class="fa-solid fa-xmark"></i>
            </div>
          </h5>
          <Form>
            <FormItem
              label="Email"
              :error="errorMessages.email"
              :required="true"
            >
              <Input
                type="email"
                placeholder="email"
                v-model="formValue.email"
              ></Input>
              <span class="text-danger" v-if="errors.email">{{
                errors.email[0]
              }}</span>
            </FormItem>

            <FormItem
              label="Designation"
              :error="errorMessages.designation"
              :required="true"
            >
              <Select
                v-model="formValue.designation"
                placeholder="Select Designation"
              >
                <Option value="Head">Head</Option>
                <Option value="Professor">Professor</Option>
                <Option value="Associate Professor">Associate Professor</Option>
                <Option value="Assistant Professor">Assistant Professor</Option>
                <Option value="Lecturer">Lecturer</Option>
              </Select>
              <span class="text-danger" v-if="errors.designation">{{
                errors.designation[0]
              }}</span>
            </FormItem>

            <FormItem
              label="Department"
              :error="errorMessages.department"
              :required="true"
            >
              <Select v-model="formValue.department" placeholder="Department">
                <Option value="CSE">CSE</Option>
                <Option value="EEE">EEE</Option>
                <Option value="ARCH">ARCH</Option>
                <Option value="CE">CE</Option>
                <Option value="BuA">BuA</Option>
                <Option value="ENG">ENG</Option>
              </Select>
              <span class="text-danger" v-if="errors.department">{{
                errors.department[0]
              }}</span>
            </FormItem>
          </Form>
        </div>
        <div slot="footer">
          <div>
            <Button class="main-btn main-btn__border" @click="closeModal">
              Cancel</Button
            >
            <Button
              class="main-btn main-btn__bg"
              @click="addTeacher"
              :disabled="isAdding"
              :loading="isAdding"
            >
              {{ isAdding ? "Adding..." : "Add" }}</Button
            >
          </div>
        </div>
      </Modal>

      <Modal v-model="deleteModal" width="360">
        <p slot="header" style="color: #7da2a9; text-align: center">
          <Icon type="close"></Icon>
          <span> Delete {{ deleteValue.email }}</span>
        </p>
        <div style="text-align: center">
          Are you sure you want delete {{ deleteValue.email }}
        </div>
        <div slot="footer">
          <Button
            style="color: #7da2a9"
            size="large"
            long
            :loading="sending"
            @click="remove"
          >
            <span v-if="!sending">Delete</span>
            <span v-else>Deleting...</span>
          </Button>
        </div>
      </Modal>
    </div>
    <div v-else>
      <section class="container">
        <div class="teacher-section">
          <div class="teacher-section--table--skeleton">
            <div class="d-block pt-5 pb-5">
              <h4 class="float-start"></h4>
              <button class="float-end"></button>
            </div>
            <table class="table table-bordered">
              <thead>
                <tr>
                  <th scope="col"></th>
                  <th scope="col"></th>
                  <th scope="col"></th>
                  <th scope="col"></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
                <tr>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                  <td scope="col"></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
export default {
  middleware: "admin",

  data() {
    return {
      errors: [],
      search: "",
      addTeacherModal: false,
      editModal: false,
      isDataLoading: true,
      isAdding: false,
      sending: false,
      loadMoreLoading: false,
      noTeacherRemaining: false,
      teachersInfo: [],
      limit: 10,
      search: "",
      formValue: {
        email: "",
        designation: "",
        department: "",
      },
      errorMessages: {
        email: "",
        designation: "",
        department: "",
      },
      editObj: {
        id: null,
        email: "",
        designation: "",
        department: "",
      },
      editErrorMessages: {
        id: null,
        email: "",
        designation: "",
        department: "",
      },
      UpdateValue: {
        indexNumber: null,
        id: null,
        email: "",
        designation: "",
        department: "",
      },
      deleteValue: {
        id: null,
        indexNumber: null,
        email: "",
      },
      deleteModal: false,
    };
  },

  methods: {
    addTeacherButton() {
      this.errors = [];
      this.addTeacherModal = true;
    },
    async closeModal() {
      this.errors = [];
      this.addTeacherModal = false;
      const res = await this.callApi("get", "/api/get_teachers");
      if (res.status == 200) {
        this.teachersInfo = res.data.data;
      } else {
        this.swr();
      }
      this.formValue.email = "";
      this.formValue.designation = "";
      this.formValue.department = "";
      this.clearErrorMessage();
    },
    clearErrorMessage() {
      (this.editErrorMessages = {
        id: null,
        email: "",
        designation: "",
        department: "",
      }),
        (this.errorMessages = {
          email: "",
          designation: "",
          department: "",
        });
    },
    async addTeacher() {
      this.errors = [];
      let validation = true;
      this.clearErrorMessage();
      if (this.formValue.email.trim() == "") {
        this.errorMessages.email = "Email is required!";
        validation = false;
      }
      if (this.formValue.designation.trim() == "") {
        this.errorMessages.designation = "Designation is required!";
        validation = false;
      }
      if (this.formValue.department.trim() == "") {
        this.errorMessages.department = "Department is required!";
        validation = false;
      }
      if (validation == false) return this.$Message.error("Validation Failed!");
      console.log("Failed");
      console.log(this.formValue);
      this.isAdding = true;
      const res = await this.callApi(
        "post",
        "/api/add_teacher",
        this.formValue
      );
      if (res.status === 201) {
        this.s("Email Added!!");
        this.closeModal();
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            this.errors = res.data.errors;
            // this.e(res.data.errors[i][0]);
          }
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
      this.errors = [];
    },

    showEdit(index) {
      if (this.teachersInfo[index].id) {
        this.UpdateValue.indexNumber = index;
        this.editObj.id = this.teachersInfo[index].id;
        this.editObj.email = this.teachersInfo[index].email;
        this.editObj.designation = this.teachersInfo[index].designation;
        this.editObj.department = this.teachersInfo[index].department;

        this.$nextTick(() => {
          if (this.$refs["teacher" + this.teachersInfo[index].id]) {
            this.$refs["teacher" + this.teachersInfo[index].id][0].focus();
          }
        });
      }
    },
    async updateTeacher() {
      this.errors = [];
      let validation = true;
      this.clearErrorMessage();
      if (this.editObj.email.trim() == "") {
        this.editErrorMessages.email = "Email is required!";
        validation = false;
      }
      if (validation == false) return this.$Message.error("Validation Failed!");

      this.sending = true;
      const res = await this.callApi(
        "post",
        "/api/teachers_update",
        this.editObj
      );

      if (res.status === 200) {
        this.reset();
        this.errors = [];
        this.teachersInfo[this.UpdateValue.indexNumber].email =
          this.editObj.email;
        this.teachersInfo[this.UpdateValue.indexNumber].designation =
          this.editObj.designation;
        this.teachersInfo[this.UpdateValue.indexNumber].department =
          this.editObj.department;
        this.s("Email Updated!!");
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            this.errors = res.data.errors;
            // this.e(res.data.errors[i][0]);
          }
        } else {
          this.swr();
        }
      }
      this.sending = false;
      this.errors = [];
    },

    showRemove(index) {
      this.deleteValue.email = this.teachersInfo[index].email;
      this.deleteValue.id = this.teachersInfo[index].id;
      console.log(this.deleteValue.id);
      this.deleteValue.indexNumber = index;
      this.deleteModal = true;
    },
    async remove() {
      let ob = {
        id: this.deleteValue.id,
      };
      this.sending = true;
      const response = await this.callApi("post", "/api/teachers_del", ob);
      if (response.status == 200) {
        this.teachersInfo.splice(this.deleteValue.indexNumber, 1);
        this.s("Email Deleted!!");
        this.deleteModal = false;
        this.sending = false;
      } else {
        this.sending = false;
        // this.editModal=false
        this.deleteModal = false;
        this.swr();
      }
    },

    async filterTeachers() {
      // this.isFilter = true;
      const res = await this.callApi(
        "get",
        `/api/get_teachers??search=${this.search}&limit=${this.limit}`
      );
      if (res.status == 200) {
        this.teachersInfo = res.data.data;
      } else {
        this.swr();
      }
      // this.isFilter = false;
    },

    async getTeachers() {
      this.isDataLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_teachers??search=${this.search}&limit=${this.limit}`
      );
      if (res.status == 200) {
        this.teachersInfo = res.data.data;
      } else {
        this.swr();
      }
      this.isDataLoading = false;
    },

    async loadMore(more) {
      if (this.noTeacherRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_teachers?limit=${this.limit}`
      );
      if (res.status == 200) {
        let prevLength = this.teachersInfo.length;
        if (this.teachersInfo.length == res.data.data.length) {
          this.noTeacherRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.teachersInfo.push(d);
          }
        }
      }
      this.loadMoreLoading = false;
    },
    async reset() {
      this.editObj.id = "";
      this.clearErrorMessage();
      this.getTeachers();
      this.errors = [];
    },
  },

  async created() {
    this.getTeachers();
  },
  mounted() {
    window.onscroll = () => {
      this.bottomOfWindow =
        window.pageYOffset + window.innerHeight >
        document.body.scrollHeight - 100;

      if (this.bottomOfWindow) {
        if (!this.loadMoreLoading) {
          this.loadMore(5);
        }
      }
    };
  },
};
</script>
<style scoped>
input {
  display: block;
  padding: 4px;
  border-bottom: 0.5px solid;
  border-radius: 5px;
  color: #555;
  width: 100%;
  text-align: center;
}

.edited {
  color: #198754;
}
.notEdited {
  color: #212529;
}
</style>
