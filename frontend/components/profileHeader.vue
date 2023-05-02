<template>
  <div>
    <div class="profile-section col-lg-10 col-md-8 m-auto">
      <div class="profile-menu">
        <div v-if="isLoading == false">
          <!--****** Profile edit for Teacher ******-->
          <template v-if="editModal && isLoading == false">
            <div
              class="container"
              v-if="
                profileInfo.userType == 'teacher' ||
                profileInfo.userType == 'admin'
              "
            >
              <div class="profile-header m-auto" v-if="editData.image">
                <img
                  :src="`${http + editData.image}`"
                  class="img-fluid"
                  type="file"
                />
                <div class="profile-header-cover" @click="deleteImage()">
                  <i class="lni lni-trash-can"></i>
                </div>
              </div>

              <div class="mt-3 mb-3">
                <Upload
                  ref="editDataUploads"
                  type="drag"
                  :multiple="false"
                  :show-upload-list="true"
                  :on-success="handleSuccess"
                  :on-error="handleError"
                  :format="['jpg', 'jpeg', 'png']"
                  :max-size="65535"
                  :on-format-error="handleFormatError"
                  :on-exceeded-size="handleMaxSize"
                  action="http://localhost:8000/api/upload_profile_image"
                >
                  <div class="profile-main-btn">
                    <i class="fa-solid fa-cloud-arrow-up"></i>
                    Upload Image
                  </div>
                </Upload>
              </div>

              <div class="plr-1rem">
                <div class="mb-2">
                  <Input
                    type="text"
                    v-model="editData.name"
                    placeholder="Name"
                  />
                  <span class="text-danger" v-if="errors.name">{{
                    errors.name[0]
                  }}</span>
                </div>
                <div class="mb-2">
                  <Select
                    v-model="editData.designation"
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
                </div>
                <div class="mb-2">
                  <Select
                    v-model="editData.department"
                    placeholder="Department"
                  >
                    <Option
                      v-for="(department, index) in departmentInfo"
                      :key="index"
                      :value="department.id"
                      >{{ department.department_name }}</Option
                    >
                  </Select>
                  <span class="text-danger" v-if="errors.department">{{
                    errors.department[0]
                  }}</span>
                </div>
                <div class="d-flex mb-2">
                  <button
                    class="profile-main-btn col-6"
                    @click="closeEditModal()"
                  >
                    Cancel
                  </button>
                  <button class="profile-main-btn col-6" @click="save()">
                    <i class="fa-solid fa-floppy-disk"></i> Save
                  </button>
                </div>
              </div>
            </div>
          </template>
          <!--****** Profile edit for Student ******-->
          <template v-if="editModal && isLoading == false">
            <div class="container" v-if="profileInfo.userType == 'student'">
              <div class="profile-header m-auto" v-if="editData.image">
                <img
                  :src="`${http + editData.image}`"
                  class="img-fluid"
                  type="file"
                />
                <div class="profile-header-cover" @click="deleteImage()">
                  <i class="lni lni-trash-can"></i>
                </div>
              </div>

              <div class="mt-3 mb-3">
                <Upload
                  ref="editDataUploads"
                  type="drag"
                  :multiple="false"
                  :show-upload-list="true"
                  :headers="{
                    'x-csrf-token': token,
                    'X-Requested-With': 'XMLHttpRequest',
                  }"
                  :on-success="handleSuccess"
                  :on-error="handleError"
                  :format="['jpg', 'jpeg', 'png']"
                  :max-size="65535"
                  :on-format-error="handleFormatError"
                  :on-exceeded-size="handleMaxSize"
                  action="http://127.0.0.1:8000/api/upload_profile_image"
                >
                  <div class="profile-main-btn">
                    <i class="fa-solid fa-cloud-arrow-up"></i>
                    Upload Image
                  </div>
                </Upload>
              </div>

              <div class="plr-1rem">
                <div class="mb-2">
                  <Input
                    type="text"
                    v-model="editData.name"
                    placeholder="Name"
                  />
                  <span class="text-danger" v-if="errors.name">{{
                    errors.name[0]
                  }}</span>
                </div>
                <div class="mb-2">
                  <Select
                    v-model="editData.department"
                    placeholder="Department"
                  >
                    <Option
                      v-for="(department, index) in departmentInfo"
                      :key="index"
                      :value="department.id"
                      >{{ department.department_name }}</Option
                    >
                  </Select>
                  <span class="text-danger" v-if="errors.department">{{
                    errors.department[0]
                  }}</span>
                </div>
                <div class="d-flex mb-2">
                  <button
                    class="profile-main-btn col-6"
                    @click="closeEditModal()"
                  >
                    Cancel
                  </button>
                  <button class="profile-main-btn col-6" @click="save()">
                    <i class="fa-solid fa-floppy-disk"></i> Save
                  </button>
                </div>
              </div>
            </div>
          </template>
          <!--****** Profile Info ******-->
          <template v-else>
            <div class="profile-header m-auto">
              <img
                :src="`${http + profileInfo.image}`"
                alt="img"
                class="img-fluid"
              />
              <div
                class="profile-header-cover"
                v-if="authUser.slug == this.$route.params.slug"
              >
                <i class="fa-solid fa-camera m-2" @click="showImage"></i>
                <i
                  class="fa-solid fa-pen-to-square m-2"
                  @click="showEditModal(profileInfo)"
                ></i>
              </div>
              <div class="profile-header-cover" @click="showImage" v-else>
                <i class="fa-solid fa-camera"></i>
              </div>
            </div>
            <h4 class="header">
              {{ profileInfo.name
              }}<span
                v-if="authUser.slug == this.$route.params.slug"
                class="btn-edit m-2"
                @click="showEditModal()"
              >
                <i class="fa-solid fa-pen" />
              </span>
            </h4>
            <p id="not">
              {{ profileInfo.designation }}
              .
              {{ profileInfo.department.department_name }}
            </p>
            <p>{{ profileInfo.email }}</p>

            <div
              class="footer"
              v-if="this.authUser.slug !== this.$route.params.slug"
            >
              <button
                class="main-btn main-btn__bg col-5 mx-1"
                v-if="sendRequest"
                @click="ignoreConnection"
              >
                <i class="fa-solid fa-clock-rotate-left"></i>
                Pending
              </button>
              <button
                class="main-btn main-btn__bg col-5 mx-1"
                v-else-if="receivedRequest"
                @click="showResponseModal('Are you want to accept ')"
              >
                <i class="fa-solid fa-user-check"></i>
                Response
              </button>
              <button
                class="main-btn main-btn__bg col-5 mx-1"
                v-else-if="approvedRequest"
                @click="showRemoveModal"
              >
                <i class="fa-solid fa-user-check"></i>
                Connected
              </button>
              <button
                class="main-btn main-btn__border col-5 mx-1"
                @click="connect"
                v-else
              >
                <!-- <i class="fa-solid fa-user-check"></i> -->
                <i class="fa-solid fa-user-plus"></i>
                Connect
              </button>
              <button
                class="main-btn main-btn__border col-5 mx-1"
                @click="handleSelect"
              >
                <i class="fa-solid fa-paper-plane"></i>
                Message
              </button>
            </div>
          </template>
          <Modal v-model="visible">
            <img :src="`${http + profileInfo.image}`" style="width: 100%" />
            <div slot="footer"></div>
          </Modal>
        </div>
        <!---******* loader *******--->
        <div class="container mb-2" v-if="isLoading == true">
          <div class="profile-header-skeleton m-auto">
            <img class="img-fluid m-auto" />
          </div>
          <div class="p-3 profile-info-skeleton">
            <h4 class="mt-1 mb-1" />
            <p class="mb-1" />
            <p />
          </div>
        </div>
        <div class="d-lg-block d-none">
          <ul class="profile-menu--list">
            <li class="profile-menu--list---item">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/profile/${this.$route.params.slug}/overview`"
                ><i class="fa-solid fa-user"></i>
                <h4>Profile</h4></nuxt-link
              >
            </li>
            <li class="profile-menu--list---item" v-if="authUser">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/profile/${this.$route.params.slug}/research`"
                ><i
                  class="fa-regular fa-folder-open"
                  v-if="$route.name == 'profile-slug-research'"
                ></i
                ><i class="fa-solid fa-folder" v-else></i>
                <h4>Research</h4></nuxt-link
              >
            </li>
            <li class="profile-menu--list---item" v-if="authUser">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/profile/${this.$route.params.slug}/project`"
                ><i
                  class="fa-regular fa-folder-open"
                  v-if="$route.name == 'profile-slug-project'"
                ></i
                ><i class="fa-solid fa-folder" v-else></i>
                <h4>Projects</h4></nuxt-link
              >
            </li>
            <li class="profile-menu--list---item" v-if="authUser">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/profile/${this.$route.params.slug}/connection`"
                ><i class="fa-solid fa-users"></i>
                <h4>Connections</h4></nuxt-link
              >
            </li>
          </ul>
        </div>
        <div class="d-lg-none">
          <profileNav />
        </div>
      </div>

      <!-- profile description -->
      <div class="profile-description menu-item">
        <div class="menu-item-box">
          <Nuxt />
        </div>
      </div>
    </div>
    <div v-if="isLoading == false">
      <Modal v-model="responseModal">
        <p slot="header" style="color: #566d7e; text-align: center">
          <Icon type="close"></Icon>
          <span>Response</span>
        </p>
        <div style="text-align: center">
          <b>{{ this.connection_title }}</b
          >?
        </div>
        <div slot="footer" class="justify-content-center d-flex">
          <Button
            class="main-btn main-btn__border"
            :loading="sending"
            @click="acceptConnection"
          >
            <span v-if="!sending">Accept</span>
            <span v-else>Accepting...</span>
          </Button>
          <Button
            class="main-btn main-btn__border"
            :loading="sending"
            @click="ignoreConnection"
          >
            <span v-if="!sending">Ignore</span>
            <span v-else>Ignoring...</span>
          </Button>
        </div>
      </Modal>
      <Modal v-model="removeModal">
        <p slot="header" style="color: #566d7e; text-align: center">
          <Icon type="close"></Icon>
          <span>Response</span>
        </p>
        <div style="text-align: center">
          <b>{{ this.connection_title }}</b>
        </div>
        <div slot="footer">
          <Button
            class="main-btn main-btn__border"
            long
            :loading="sending"
            @click="ignoreConnection"
          >
            <span v-if="!sending">Remove</span>
            <span v-else>Removing...</span>
          </Button>
        </div>
      </Modal>
    </div>
  </div>
</template>
<script>
import ProfileNav from "./profileNav";
const { io } = require("socket.io-client");

export default {
  name: "Profile",

  data() {
    return {
      socket: null,
      isChatLoading: false,
      isLoading: false,
      visible: false,
      data: {
        image: "",
        name: "",
        designation: "",
        department: "",
        about: "",
        //education
        institute: "",

        Skills: "",
      },
      editModal: false,
      profileInfo: [],
      editData: {
        image: "",
        name: "",
        designation: "",
        department: "",
        about: "",
        skills: "",
        interests: "",
      },
      index: -1,
      user_slug: "",
      token: "",
      connection_id: "",
      connection_title: "",
      isIconImageNew: false,
      isEditingItem: false,
      sendRequest: false,
      receivedRequest: false,
      approvedRequest: false,
      responseModal: false,
      removeModal: false,
      sending: false,
      errors: [],
      selectedChatCompare: "",
      http: this.$config.IMAGE_URL,
    };
  },
  components: {
    ProfileNav,
  },
  methods: {
    async save() {
      if (this.editData.name.trim() == "") return this.e("Name is required");
      if (this.editData.designation == "")
        return this.e("Designation is required");
      if (this.editData.department == "")
        return this.e("Department is required");
      const res = await this.callApi(
        "post",
        `/api/edit_profile`,
        this.editData
      );
      if (res.status === 200) {
        this.profileInfo.name = this.editData.name;
        this.profileInfo.designation = this.editData.designation;
        this.profileInfo.department_id = this.editData.department;
        this.authUser.image = this.editData.image;
        this.getProfileInfo();
        this.s("Profile has been updated successfully!");
        this.editModal = false;
        this.errors = [];
        // window.location = `/profile/${this.profileInfo.id}`;
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
    },
    showImage() {
      this.visible = true;
    },
    showEditModal() {
      let obj = {
        id: this.profileInfo.id,
        image: this.profileInfo.image,
        name: this.profileInfo.name,
        designation: this.profileInfo.designation,
        department: parseInt(this.profileInfo.department_id),
      };
      this.editModal = true;
      this.editData = obj;
      this.isEditingItem = true;
    },
    handleSuccess(res, file) {
      res = `${res}`;

      this.$refs.editDataUploads.clearFiles();
      return (this.editData.image = res);
    },
    handleError(res, file) {
      this.$Notice.warning({
        title: "The file format is incorrect",
        desc: `${
          file.errors.file.length
            ? file.errors.file[0]
            : "Something went wrong!"
        }`,
      });
    },
    handleFormatError(file) {
      this.$Notice.warning({
        title: "The file format is incorrect",
        desc:
          "File format of " +
          file.name +
          " is incorrect, please select jpg or png.",
      });
    },
    handleMaxSize(file) {
      this.$Notice.warning({
        title: "Exceeding file size limit",
        desc: "File  " + file.name + " is too large, no more than 2M.",
      });
    },
    async deleteImage() {
      let image;

      image = this.editData.image;
      this.editData.image = "download.jpg";
      this.$refs.editDataUploads.clearFiles();
      const res = await this.callApi("post", "/api/delete_profile_image", {
        imageName: image,
      });
      if (res.status != 200) {
        this.editData.image = image;
        this.swr();
      }
    },
    closeEditModal() {
      this.isEditingItem = false;
      this.editModal = false;
    },

    async connect() {
      console.log("inside connect");
      this.sendRequest = true;
      const res = await this.callApi(
        "post",
        `/api/add_connection?id=${this.profileInfo.id}`
      );
      if (res.status == 201) {
        this.connection = res.data.data;
        this.callNotification();
      } else {
        this.sendRequest = false;
      }
    },
    async acceptConnection() {
      this.approvedRequest = true;
      this.receivedRequest = false;
      this.responseModal = false;
      const res = await this.callApi(
        "post",
        `/api/accept_connection?id=${this.connection.id}&user_id=${this.connection.user1.id}`
      );
      if (res.status == 201) {
        this.callNotification();
      } else {
        this.swr();
      }
    },
    async ignoreConnection() {
      // console.log(this.connection.user2.id);
      this.approvedRequest = false;
      this.receivedRequest = false;
      this.approvedRequest = false;
      this.sendRequest = false;
      this.responseModal = false;
      this.removeModal = false;
      const res = await this.callApi(
        "post",
        `/api/ignore_connection?id=${this.connection.id}&user_id=${this.profileInfo.id}`
      );
      if (res.status == 201) {
        console.log("success");
        this.callNotification();
      } else {
        this.swr();
      }
    },
    showResponseModal() {
      this.connection_title =
        "Are you sure you want to accept " +
        this.connection.user1.name +
        " as your connection";
      this.responseModal = true;
    },
    showRemoveModal() {
      this.connection_title =
        "Are you sure you want to remove " +
        this.connection.user1.name +
        " from your connection?";
      this.removeModal = true;
    },
    async connectionStatus() {
      this.user_slug = this.$route.params.slug;
      this.isLoading = true;
      this.approvedRequest = false;
      this.receivedRequest = false;
      this.sendRequest = false;
      const res = await this.callApi(
        "get",
        `/api/connection_status?slug=${this.user_slug}`
      );
      // if (res.status == 200) {
      // }
      if (res.status == 201) {
        this.approvedRequest = true;
      }
      if (res.status == 202) {
        this.receivedRequest = true;
      }
      if (res.status == 203) {
        this.sendRequest = true;
      }
      this.connection = res.data.data;
      this.isLoading = false;
    },
    async getProfileInfo() {
      // this.token = window.Laravel.csrfToken;

      this.user_slug = this.$route.params.slug;
      this.isLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_profile_header_info/${this.user_slug}`
      );

      if (res.status == 200) {
        this.profileInfo = res.data.user;
      } else {
        this.swr();
      }
      this.isLoading = false;
    },
    callNotification() {
      let notificationObj = {
        id: this.profileInfo.id,
      };
      this.socket.emit("notification", notificationObj);
    },
    async handleSelect() {
      let info = {
        selectedUserId: this.profileInfo.id,
        selectedUserImage: this.profileInfo.image,
        selectedUserSlug: this.profileInfo.slug,
        selectedUserName: this.profileInfo.name,
      };
      let user = {
        id: this.profileInfo.id,
        image: this.profileInfo.image,
        slug: this.profileInfo.slug,
        name: this.profileInfo.name,
      };
      this.$store.commit("setSelectedUserInfo", info);
      let obj = {
        from_id: this.authUser.id,
        to_id: this.profileInfo.id,
      };
      const res = await this.callApi("post", `/api/add_conversation`, obj);
      if (res.status == 200) {
        this.getSelectedUserChat(user, res.data.data[0].id);
      } else if (res.status == 201) {
        this.getSelectedUserChat(user, res.data.data[0].id);
      }
    },
    async getSelectedUserChat(user, index) {
      this.$store.commit("setIsChatBox", true);
      let info = {
        room_id: index,
        selectedUserId: user.id,
        selectedUserImage: user.image,
        selectedUserSlug: user.slug,
        selectedUserName: user.name,
      };
      this.$store.commit("setSelectedUserInfo", info);

      let roomId = index;
      this.isActive = true;
      this.selectedChatCompare = this.selectedUserInfo;
      // window.history.pushState({}, null, `${this.$route.path}`);
      this.isChatLoading = true;
      const response = await this.callApi(
        "get",
        `/api/get_chat?limit=${3}&roomId=${roomId}`
      );
      if (response.status == 200) {
        this.$store.commit("setMessages", response.data.data);
        this.socket.emit("join chat", roomId);
      } else this.swr();
      this.isChatLoading = false;
    },
  },

  // to perform "side effects" in reaction to state changes
  watch: {
    "$route.params.slug"(oldValue, newValue) {
      if (oldValue != newValue) {
        console.log("route is changing!");
        this.getProfileInfo();
        this.connectionStatus();
      }
    },
  },
  async created() {
    this.getProfileInfo();
    this.connectionStatus();
  },
  mounted() {
    this.socket = io("http://localhost:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
  },
};
</script>
<style scoped></style>
