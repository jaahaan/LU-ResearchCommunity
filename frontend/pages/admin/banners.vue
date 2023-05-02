<template>
  <div class="connection--item mt-40">
    <div v-if="!isOrder" class="banner">
      <h5 class="post-title">
        Banners
        <div>
          <a class="main-btn float-end" @click="addBannerButton">
            Add New Banner
          </a>

          <a
            class="main-btn float-end me-2"
            v-if="banners"
            @click="getOrderBanners"
            >Order Banners</a
          >
        </div>
      </h5>

      <div v-if="isDataLoading" class="loader-lg">
        <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
      </div>
      <div v-else>
        <section class="container">
          <div class="teacher-section">
            <div class="teacher-section--table">
              <div v-if="banners == ''">
                <div class="_card"><h1>No Banner Found</h1></div>
              </div>
              <table class="table table-bordered" v-else>
                <thead>
                  <tr class="banner">
                    <th scope="col">Image</th>
                    <th scope="col">Active Status</th>
                    <th scope="col">Delete</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="(item, index) in banners"
                    :key="index"
                    class="banner"
                  >
                    <td class="table-image banner">
                      <img :src="`${http + item.image}`" />
                      <div class="table-image-cover">
                        <i
                          class="lni lni-search-alt"
                          @click="handleView(item.image, index)"
                        ></i>
                      </div>
                    </td>

                    <td>
                      <!-- <i
                      class="fa-solid fa-circle-check"
                      v-bind:class="{ active: item.link }"
                      @click="showActiveBanner(index)"
                    ></i> -->
                      <i-switch
                        v-model="item.isActive"
                        @on-change="changeActive(index)"
                        :loading="editIndex == index"
                        :true-value="1"
                        :false-value="0"
                        true-color="#4caf50"
                        false-color="#ed2939"
                      />
                    </td>
                    <td>
                      <!-- <i
                      class="fa-solid fa-pen-to-square"
                      @click="showEdit(index)"
                    ></i> -->
                      <i
                        class="lni lni-trash-can"
                        @click="showRemove(index)"
                      ></i>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <Modal v-model="addBannerModal" :closable="false">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>Add New Banner</div>
              <div class="btn-edit text-danger" @click="closeModal">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form>
              <FormItem
                label="Image"
                :error="errorMessages.image"
                :required="true"
              >
                <Upload
                  ref="uploads"
                  type="drag"
                  :multiple="true"
                  :show-upload-list="false"
                  :on-success="handleImageSuccess"
                  :on-error="handleError"
                  :format="['jpg', 'jpeg', 'png']"
                  :on-exceeded-size="handleMaxSize"
                  :max-size="65535"
                  :on-format-error="handleFormatError"
                  action="http://127.0.0.1:8000/api/upload"
                >
                  <div style="padding: 5px 0">
                    <Icon
                      type="ios-cloud-upload"
                      size="22"
                      style="color: #3399ff"
                    ></Icon>
                    Upload Image
                  </div>
                </Upload>
                <div
                  class="demo-upload-list"
                  v-if="data.images"
                  v-for="(image, index) in data.images"
                >
                  <img :src="`${http + image}`" />
                  <div class="demo-upload-list-cover">
                    <Icon
                      type="ios-trash-outline"
                      @click="deleteImage(index)"
                    ></Icon>
                  </div>
                </div>
                <span class="text-danger" v-if="errors.images">{{
                  errors.images
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
                @click="addBanner"
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
            <span> Delete Banner</span>
          </p>
          <div style="text-align: center">
            Are you sure you want delete {{ deleteValue.title }}?
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

        <Modal v-model="activeModal" width="360">
          <p slot="header" style="color: #7da2a9; text-align: center">
            <Icon type="close"></Icon>
            <span> {{ deleteValue.title }}</span>
          </p>
          <div style="text-align: center">
            Are you sure you want to {{ deleteValue.title }}?
          </div>
          <div slot="footer">
            <Button
              style="color: #7da2a9"
              size="large"
              long
              :loading="sending"
              @click="activeBanner"
            >
              {{ deleteValue.title }}
            </Button>
          </div>
        </Modal>
        <Modal v-model="visible">
          <img :src="imgName" style="width: 100%" />
          <div slot="footer"></div>
        </Modal>
      </div>
    </div>
    <div v-else>
      <h5 class="post-title">
        Reorder Banners<a class="main-btn float-end" @click="getBanners"
          >Cancel</a
        >
      </h5>
      <section class="container">
        <div class="teacher-section">
          <div class="teacher-section--table">
            <div v-if="banners.length == 0" class="loader-lg">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
            </div>
            <table class="table table-bordered" v-else>
              <thead>
                <tr class="tr">
                  <th scope="col">Order No.</th>
                  <th scope="col">Image</th>
                </tr>
              </thead>
              <tbody>
                <draggable
                  :list="banners"
                  @change="log"
                  :disabled="!enabled"
                  class="list-group"
                  ghost-class="ghost"
                  @start="dragging = true"
                  @end="dragging = false"
                >
                  <tr class="li active" v-for="(data, index) in banners">
                    <!-- {{ page }} -->
                    <td>
                      <span v-if="page > 1">{{
                        index + 1 + (page - 1) * 20
                      }}</span>
                      <span v-else>{{ index + 1 }}</span>
                    </td>
                    <td>
                      <img :src="`${http + data.image}`" />
                    </td>
                  </tr>
                </draggable>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
import draggable from "vuedraggable";

export default {
  middleware: "admin",
  components: {
    name: "simple",
    display: "Simple",
    order: 0,
    draggable,
  },
  data() {
    return {
      errors: [],
      search: "",
      addBannerModal: false,
      editModal: false,
      isDataLoading: true,
      isAdding: false,
      sending: false,
      visible: false,
      enabled: true,

      banners: [],
      data: {
        images: [],
      },
      imageName: [],
      imgName: "",
      index: "",
      errorMessages: {
        images: "",
      },
      editObj: {
        id: null,
        image: "",
      },
      editErrorMessages: {
        id: null,
        image: "",
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
        title: "",
      },
      deleteModal: false,
      activeModal: false,
      editIndex: -1,
      dataOrderBanner: [],
      new_list: [],
      newData: [],
      page: 1,
      firstItem: 0,
      lastItem: 1,
      disabled: 0,
      isOrder: false,
      http: this.$config.IMAGE_URL,
    };
  },

  methods: {
    handleView(item, index) {
      this.imgName = this.http + item;
      this.index = index;
      this.visible = true;
    },
    addBannerButton() {
      this.errors = [];
      this.addBannerModal = true;
    },
    handleImageSuccess(res, file) {
      // this.iconImageName = `${res}`;
      this.imageName.push(`${res}`);

      res = `${res}`;
      console.log(res);
      // this.data.iconImage = res;
      this.data.images.push(res);
    },
    async deleteImage(index) {
      let image;

      // image = this.iconImageName;

      image = this.data.images[index];
      this.data.images.splice(index, 1);
      const res = await this.callApi("post", "/api/delete_image", {
        imageName: image,
      });
      // this.imageName.splice(index, 1);
      if (res.status != 200) {
        this.swr();
      }
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
    handleView(item, index) {
      this.imgName = this.http + item;
      this.index = index;
      this.visible = true;
    },
    async closeModal() {
      this.errors = [];
      this.addBannerModal = false;
      const res = await this.callApi("get", "/api/get_banners");
      if (res.status == 200) {
        this.banners = res.data.data;
      } else {
        this.swr();
      }
      this.data.images = [];
      this.clearErrorMessage();
    },
    clearErrorMessage() {
      (this.editErrorMessages = {
        id: null,
        images: "",
      }),
        (this.errorMessages = {
          images: "",
        });
    },
    async addBanner() {
      this.errors = [];
      // let validation = true;
      // this.clearErrorMessage();
      // if (this.data.images.length < 1) {
      //   this.errorMessages.image = "Image is required!";
      //   validation = false;
      // }

      // if (validation == false) return this.$Message.error("Validation Failed!");
      // console.log("Failed");
      console.log(this.data);
      this.isAdding = true;
      const res = await this.callApi("post", "/api/add_banner", this.data);
      if (res.status === 200) {
        this.s("Banner Added!!");
        this.errors = [];

        this.closeModal();
      } else {
        if (res.status == 422) {
          if (res.data.images) {
            this.errors.images = res.data.images[0];
          }
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
    },

    showEdit(index) {
      if (this.banners[index].id) {
        this.UpdateValue.indexNumber = index;
        this.editObj.id = this.banners[index].id;
        this.editObj.email = this.banners[index].email;
        this.editObj.designation = this.banners[index].designation;
        this.editObj.department = this.banners[index].department;

        this.$nextTick(() => {
          if (this.$refs["teacher" + this.banners[index].id]) {
            this.$refs["teacher" + this.banners[index].id][0].focus();
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
        this.banners[this.UpdateValue.indexNumber].email = this.editObj.email;
        this.banners[this.UpdateValue.indexNumber].designation =
          this.editObj.designation;
        this.banners[this.UpdateValue.indexNumber].department =
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
      this.deleteValue.title = "Banner";
      this.deleteValue.id = this.banners[index].id;
      console.log(this.deleteValue.id);
      this.deleteValue.indexNumber = index;
      this.deleteModal = true;
    },

    async changeActive(index) {
      console.log(index);
      let ob = {
        id: this.banners[index].id,
        status: this.banners[index].isActive,
      };
      // this.sending = true;
      this.editIndex = index;

      const res = await this.callApi("post", "/api/active_banner", ob);

      if (res.status == 200) {
        // this.s("Great!", "Product has been Modified successfully!");
        if (this.banners[index].isActive == 1) {
          this.s_msg("Activated");
        } else {
          this.e_msg("Deactivated");
        }
      } else if (res.status == 401) {
        this.e_msg(res.data.msg);
        this.banners[index].isActive = 0;
      } else {
        this.swr();
      }
      this.editIndex = -1;
    },
    async activeBanner() {
      let ob = {
        id: this.deleteValue.id,
        status: this.deleteValue.title,
      };
      this.sending = true;
      const res = await this.callApi("post", "/api/active_banner", ob);
      if (res.status == 200) {
        this.banners[this.deleteValue.indexNumber].link = res.data.data.link;
      } else {
        this.swr();
      }
      this.sending = false;
      this.activeModal = false;
    },
    async remove() {
      let ob = {
        id: this.deleteValue.id,
      };
      this.sending = true;

      const response = await this.callApi("post", "/api/del_banner", ob);
      const res = await this.callApi("post", "/api/delete_image", {
        imageName: this.banners[this.deleteValue.indexNumber].image,
      });
      if (response.status == 200 && res.status === 200) {
        this.banners.splice(this.deleteValue.indexNumber, 1);
        this.s("Banner Deleted!!");
        this.deleteModal = false;
      } else {
        // this.editModal=false
        this.deleteModal = false;
        this.swr();
      }
      this.sending = false;
    },

    async getBanners() {
      this.isOrder = false;
      this.isDataLoading = true;
      const res = await this.callApi("get", "/api/get_banners");
      if (res.status == 200) {
        this.banners = res.data.data;
      } else {
        this.swr();
      }
      this.isDataLoading = false;
    },

    newList() {
      this.new_list = [];
      this.banners.forEach((data, i) => {
        this.new_list.push(data.order_no);
      });
      return (this.disabled = 0);
    },
    log: function (e) {
      this.newData = [];
      this.banners.forEach((data, i) => {
        let obj = {
          id: data.id,
          order_no: this.new_list[i],
        };
        this.newData.push(obj);
        // this.newList[i].order=data.id
      });
      this.resetProduct();
    },
    async getOrderBanners() {
      this.disabled = 1;
      this.isOrder = true;
      this.isDataLoading = true;
      let url = `/api/main_banner_all?page=${this.page}&lastItem=${this.firstItem}`;
      const res = await this.callApi("get", url);
      if (res.status == 200) {
        this.banners = res.data;
        this.firstItem = res.data[0].order_no;
        this.lastItem = res.data[this.banners.length - 1].order_no;
        console.log(this.banners.length);
        this.newList();
      } else {
        this.swr();
      }
      this.isDataLoading = false;
    },
    async resetProduct() {
      this.disabled = 1;
      const response = await this.callApi(
        "post",
        "/api/reset_banner",
        this.newData
      );
      if (response.status == 200) {
        this.s_msg("Updated Successfully!");
        this.resetOrder();
      } else this.swr();
    },
    async resetOrder() {
      this.disabled = 1;
      let url = `/api/main_banner_all?page=${this.page}&lastItem=${this.firstItem}`;
      const res = await this.callApi("get", url);
      if (res.status == 200) {
        this.banners = res.data;
        this.firstItem = res.data[0].order_no;
        this.lastItem = res.data[this.banners.length - 1].order_no;
        console.log(this.banners.length);
        this.newList();
      } else {
        this.swr();
      }
    },
    async reset() {
      this.editObj.id = "";
      this.clearErrorMessage();
      this.getBanners();
      this.errors = [];
    },
  },

  async created() {
    this.getBanners();
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

.tr {
  list-style-type: none;
  width: 100%;
  display: flex;
  justify-content: space-around;
  align-items: center;
  /* flex:1; */
  gap: 15px;
  text-align: center;
  padding: 5px;
  margin: 8px auto;
}
tr:not(.tr):not(.banner) {
  list-style-type: none;
  width: 100%;
  display: flex;
  border: 1px solid rgb(85, 82, 82);
  justify-content: space-around;
  align-items: center;
  /* flex:1; */
  gap: 15px;
  text-align: center;
  padding: 5px;
  margin: 8px auto;
}

tr:hover:not(.tr):not(.banner) {
  cursor: move;
}
tr td:not(.banner) {
  font-size: 16px;
  flex-basis: 180px;
  width: 150px;
  word-break: break-all;
  /* min-width: 150px; */
}
/* tr div{
        margin-right: 0;
        justify-self: flex-end;
    } */
tr td Button {
  margin: 0 3px 2px 0;
}
tr td Button:hover {
  cursor: pointer;
}
.active:active {
  background-color: #021e27 !important;
  color: #fff;
  width: 100%;
  cursor: move;
  border: 1px solid black;
}
</style>
