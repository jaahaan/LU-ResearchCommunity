<template>
  <div>
    <!--****** Add Project box ******-->

    <template
      v-if="isLoading == false && showProjectForm == false && posts == ''"
    >
      <div v-if="authUser.slug == route_slug">
        <div class="_card" v-on:click="showForm()">
          <button>
            <h1>
              No Project Found.<br />
              <i class="lni lni-folder"></i> Add Your Project
            </h1>
          </button>
        </div>
      </div>
      <div v-else>
        <div class="_card"><h1>No Project Found</h1></div>
      </div>
    </template>

    <!--****** Add Project form ******-->
    <template v-if="showProjectForm == true">
      <div class="research-post--item">
        <h5 class="post-title">
          <div>Add Project</div>
          <div class="btn-edit text-danger" @click="reset()">
            <i class="fa-solid fa-xmark"></i>
          </div>
        </h5>
        <Form label-position="top">
          <FormItem label="Project Name *">
            <Input v-model="data.title" placeholder="Project Name"></Input>
            <span class="text-danger" v-if="errors.title">{{
              errors.title[0]
            }}</span>
          </FormItem>

          <FormItem label="Description">
            <Input
              v-model="data.abstract"
              type="textarea"
              :autosize="{ minRows: 2, maxRows: 5 }"
              placeholder="Write description..."
            ></Input>
            <span class="text-danger" v-if="errors.abstract">{{
              errors.abstract[0]
            }}</span>
          </FormItem>
          <FormItem label="Team Member">
            <Select
              filterable
              multiple
              placeholder="Select Team Member"
              v-model="data.author_id"
              :remote-method="getAuthors"
            >
              <Option
                v-for="(user, index) in users"
                :value="user.id"
                :key="index"
                >{{ user.name }}</Option
              >
            </Select>
          </FormItem>

          <FormItem label="Affiliation">
            <Input placeholder="Affiliation" v-model="data.affiliation" />
            <span class="text-danger" v-if="errors.affiliation">{{
              errors.affiliation[0]
            }}</span>
          </FormItem>
          <FormItem label="Project URL">
            <Input type="url" v-model="data.url" placeholder="Project URL" />
            <span class="text-danger" v-if="errors.url">{{
              errors.url[0]
            }}</span>
          </FormItem>
          <FormItem label="Image">
            <Upload
              ref="uploads"
              type="drag"
              :multiple="true"
              :show-upload-list="false"
              :on-success="handleImageSuccess"
              :format="['jpg', 'jpeg', 'png']"
              :on-format-error="handleFormatError"
              :on-error="handleError"
              :on-exceeded-size="handleMaxSize"
              :max-size="2048"
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
          </FormItem>
          <FormItem label="Attachment">
            <div v-if="!attachmentName">
              <Upload
                ref="uploadAttachment"
                :multiple="false"
                :on-success="handleSuccess"
                :format="['pdf', 'docx', 'txt', 'zip']"
                :on-format-error="handleFormatError"
                :on-exceeded-size="handleMaxSize"
                :on-remove="deleteAttachment"
                :max-size="60048"
                type="drag"
                action="http://127.0.0.1:8000/api/upload_attachment"
              >
                <div class="profile-main-btn">
                  <i class="fa-solid fa-cloud-arrow-up"></i>
                  Upload Attachment
                </div>
              </Upload>
            </div>
            <div v-else-if="isAttachmentLoading" class="loader-sm">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
            </div>
            <div v-else-if="attachmentName" class="attachmentName">
              <span class="c-pointer">{{ this.attachmentName }}</span>
              <span @click="deleteAttachment"
                ><i class="lni lni-trash-can c-pointer"></i
              ></span>
            </div>
          </FormItem>

          <div class="row">
            <div class="col-6">
              <FormItem label="Start Date">
                <DatePicker
                  type="month"
                  v-model="data.start_date"
                  placeholder="Start Date"
                  class="d-block"
                ></DatePicker>
                <span class="text-danger" v-if="errors.start_date">{{
                  errors.start_date[0]
                }}</span>
              </FormItem>
            </div>

            <div class="col-6">
              <FormItem label="End Date (or expected)">
                <DatePicker
                  type="month"
                  v-model="data.end_date"
                  placeholder="End Date (or expected)"
                  class="d-block"
                ></DatePicker>
                <span class="text-danger" v-if="errors.end_date">{{
                  errors.end_date[0]
                }}</span>
              </FormItem>
            </div>
          </div>
        </Form>

        <div class="footer">
          <div></div>
          <div>
            <button class="main-btn main-btn__border" @click="reset">
              Cancel
            </button>
            <Button
              class="main-btn main-btn__bg"
              @click="save"
              :disabled="loading"
              :loading="loading"
              ><i class="fa-solid fa-floppy-disk"></i>
              {{ loading ? "Saving..." : "Save" }}</Button
            >
          </div>
        </div>
      </div>
    </template>

    <!--**** Projects ****-->

    <template
      v-if="posts != '' && isLoading == false && showProjectForm == false"
    >
      <div>
        <div>
          <div class="section-header">
            <div>
              <h3>Projects</h3>
            </div>
            <div
              v-if="authUser.slug == route_slug && edit_id == ''"
              class="btn-edit"
              @click="showForm()"
            >
              <i class="lni lni-plus"></i>
            </div>
          </div>
        </div>
        <div
          class="research-post--item"
          v-for="(research, index) in posts"
          :key="index"
        >
          <template v-if="edit_id == research.id">
            <h5 class="post-title">
              <div>Edit Project</div>
              <div class="btn-edit text-danger" @click="reset">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form label-position="top">
              <FormItem label="Project Name *">
                <Input
                  v-model="editData.title"
                  placeholder="Project Name"
                ></Input>
                <span class="text-danger" v-if="errors.title">{{
                  errors.title[0]
                }}</span>
              </FormItem>

              <FormItem label="Description">
                <Input
                  v-model="editData.abstract"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 5 }"
                  placeholder="Write description..."
                ></Input>
                <span class="text-danger" v-if="errors.abstract">{{
                  errors.abstract[0]
                }}</span>
              </FormItem>
              <FormItem label="Team Member">
                <Select
                  filterable
                  multiple
                  placeholder="Select Team Member"
                  v-model="editData.author_id"
                  :remote-method="getAuthors"
                >
                  <Option
                    v-for="(user, i) in users"
                    :value="user.id"
                    :key="i"
                    >{{ user.name }}</Option
                  >
                </Select>
              </FormItem>
              <FormItem label="Affiliation">
                <Input
                  placeholder="Affiliation"
                  v-model="editData.affiliation"
                />
                <span class="text-danger" v-if="errors.affiliation">{{
                  errors.affiliation[0]
                }}</span>
              </FormItem>
              <FormItem label="Project URL">
                <Input
                  type="url"
                  v-model="editData.url"
                  placeholder="Project URL"
                />
                <span class="text-danger" v-if="errors.url">{{
                  errors.url[0]
                }}</span>
              </FormItem>
              <FormItem label="Image">
                <Upload
                  ref="editDataUploads"
                  type="drag"
                  :multiple="true"
                  :show-upload-list="false"
                  :on-success="handleImageSuccess"
                  :format="['jpg', 'jpeg', 'png']"
                  :on-format-error="handleFormatError"
                  :on-error="handleError"
                  :on-exceeded-size="handleMaxSize"
                  :max-size="65535"
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
                  v-if="editData.images"
                  v-for="(image, index) in editData.images"
                >
                  <img :src="`${http + image}`" />
                  <div class="demo-upload-list-cover">
                    <Icon
                      type="ios-trash-outline"
                      @click="deleteImage(index)"
                    ></Icon>
                  </div>
                </div>
              </FormItem>

              <FormItem label="Attachment">
                <div v-if="!attachmentName">
                  <Upload
                    ref="uploadAttachmentEdit"
                    :multiple="false"
                    :show-upload-list="false"
                    :on-success="handleSuccess"
                    :format="['pdf', 'docx', 'txt', 'mp4', 'mp3', 'zip']"
                    :on-format-error="handleFormatError"
                    :on-remove="handleRemove"
                    :max-size="65535"
                    type="drag"
                    action="http://127.0.0.1:8000/api/upload_attachment"
                  >
                    <div class="profile-main-btn">
                      <i class="fa-solid fa-cloud-arrow-up"></i>
                      Upload Attachment
                    </div>
                  </Upload>
                </div>
                <div v-else-if="isAttachmentLoading" class="loader-sm">
                  <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
                </div>
                <div v-else-if="attachmentName" class="attachmentName">
                  <span class="c-pointer">{{ attachmentName }}</span>
                  <span @click="deleteAttachment"
                    ><i class="lni lni-trash-can c-pointer"></i
                  ></span>
                </div>
              </FormItem>

              <div class="row">
                <div class="col-6">
                  <FormItem label="Start Date">
                    <DatePicker
                      type="month"
                      v-model="editData.start_date"
                      placeholder="Start Date"
                      class="d-block"
                    ></DatePicker>
                    <span class="text-danger" v-if="errors.start_date">{{
                      errors.start_date[0]
                    }}</span>
                  </FormItem>
                </div>

                <div class="col-6">
                  <FormItem label="End Date (or expected)">
                    <DatePicker
                      type="month"
                      v-model="editData.end_date"
                      placeholder="End Date (or expected)"
                      class="d-block"
                    ></DatePicker>
                    <span class="text-danger" v-if="errors.end_date">{{
                      errors.end_date[0]
                    }}</span>
                  </FormItem>
                </div>
              </div>
            </Form>

            <div class="footer">
              <div></div>
              <div>
                <Button
                  class="main-btn main-btn__border"
                  @click="deletePost"
                  :disabled="deleting"
                  :loading="deleting"
                >
                  {{ deleting ? "Deleting..." : "Delete" }}</Button
                >
                <Button
                  class="main-btn main-btn__bg"
                  @click="update"
                  :disabled="loading"
                  :loading="loading"
                  ><i class="fa-solid fa-floppy-disk"></i>
                  {{ loading ? "Saving..." : "Save" }}</Button
                >
              </div>
            </div>
          </template>
          <template v-else>
            <h5 class="post-title">
              <nuxt-link :to="`/description/${research.slug}/overview`"
                ><h5>{{ research.title }}</h5></nuxt-link
              >
              <div
                v-if="authUser.slug == route_slug"
                class="btn-edit"
                @click="showEdit(index)"
              >
                <i class="lni lni-pencil"></i>
              </div>
            </h5>
            <div class="post-sub-title">
              <p v-if="research.end_date">
                {{ research.start_date }} -
                {{ research.end_date }}
              </p>
              <p v-else>{{ research.start_date }} - Ongoing</p>
            </div>

            <div class="post-sub-title" v-if="research.affiliation">
              <p>
                <i class="fa-solid fa-graduation-cap"></i> Associated with
                {{ research.affiliation }}
              </p>
            </div>

            <hooper
              :settings="hooperImage"
              :wheelControl="false"
              v-if="research.images.length > 0"
            >
              <slide
                class="post-image"
                v-for="(image, index) in research.images"
                :key="index"
              >
                <img :src="`${http + image.image_name}`" />
                <div class="post-image-cover">
                  <i
                    class="lni lni-search-alt"
                    @click="handleView(image.image_name, index)"
                  ></i>
                </div>
              </slide>

              <hooper-navigation
                slot="hooper-addons"
                class="hooper-relatedResearch_button"
              ></hooper-navigation>
            </hooper>

            <p v-if="research.abstract != null">
              {{ research.abstract.substring(0, 190) }}
              ...
              <nuxt-link :to="`/description/${research.slug}/overview`"
                >See more</nuxt-link
              >
            </p>
            <div v-if="research.authors.length">
              <div v-if="research.authors.length > 1">
                <p
                  v-if="research.type == 'Project'"
                  class="post-sub-title mt-2"
                >
                  Team Members:
                  <span v-for="(author, index) in research.authors">
                    <nuxt-link
                      :to="`/profile/${author.slug}/overview`"
                      class="authors"
                      >{{ author.name }} </nuxt-link
                    ><span
                      class="dot"
                      v-if="research.authors.length - 1 > index"
                      >•</span
                    >
                  </span>
                </p>
                <p v-else class="post-sub-title mt-2">
                  Authors:
                  <span v-for="(author, index) in research.authors">
                    <nuxt-link
                      :to="`/profile/${author.slug}/overview`"
                      class="authors"
                      >{{ author.name }} </nuxt-link
                    ><span
                      class="dot"
                      v-if="research.authors.length - 1 > index"
                      >•</span
                    >
                  </span>
                </p>
              </div>
              <div v-else>
                <p
                  class="post-sub-title mt-2"
                  v-if="research.type == 'Project'"
                >
                  Team Member:
                  <span v-for="(author, index) in research.authors">
                    <nuxt-link
                      :to="`/profile/${author.slug}/overview`"
                      class="authors"
                      >{{ author.name }}</nuxt-link
                    ><span
                      class="dot"
                      v-if="research.authors.length - 1 > index"
                      >•</span
                    ></span
                  >
                </p>
                <p class="post-sub-title mt-2" v-else>
                  Author:
                  <span v-for="(author, index) in research.authors">
                    <nuxt-link
                      :to="`/profile/${author.slug}/overview`"
                      class="authors"
                      >{{ author.name }}
                    </nuxt-link>
                    <span class="dot" v-if="research.authors.length - 1 > index"
                      >•</span
                    >
                  </span>
                </p>
              </div>
            </div>
            <div class="post-sub-title">
              <p>
                {{ research.formatedDateTime }}
                <span class="dot">•</span>
                <a v-if="research.read_count > 1"
                  >{{ research.read_count }} Reads</a
                ><a v-else-if="research.read_count <= 1"
                  >{{ research.read_count }} Read</a
                >
                <span class="dot">•</span>
                <a>{{ research.upVote }} UpVote</a>
                <span class="dot">•</span>
                <a>{{ research.downVote }} DownVote</a>
              </p>
            </div>
            <div class="footer">
              <p>
                <a
                  v-if="research.attachment && authUser"
                  class="main-btn main-btn__bg px-lg-4"
                  :href="`${$config.BASE_URL}/api/download_attachment/${research.attachment}`"
                  >Download <i class="fa-solid fa-download"
                /></a>
                <a
                  class="main-btn main-btn__bg px-lg-5"
                  :href="`${research.url}`"
                  v-if="research.url"
                  target="_blank"
                >
                  Link <i class="fa-solid fa-arrow-up-right-from-square"></i
                ></a>
              </p>

              <p v-if="authUser">
                <a v-if="research.like_count" @click="getLikedUser(index)">
                  {{ research.like_count }}
                </a>

                <a
                  v-on:click="like(index)"
                  v-bind:class="{
                    active: research.authUserLike == 'yes',
                  }"
                >
                  <i class="fa-solid fa-thumbs-up"></i>
                </a>
              </p>
            </div>
          </template>
        </div>
        <div v-if="loadMoreLoading && !noPostRemaining" class="loader-lg">
          <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
        </div>
      </div>
    </template>
    <!--**** loader ****-->
    <template v-if="isLoading == true">
      <div class="section-header__skeleton">
        <h3></h3>
        <i></i>
      </div>
      <div class="research-post--skeleton--item">
        <div class="post-title-skeleton">
          <p></p>
        </div>
        <div class="post-sub-title-skeleton">
          <p></p>
        </div>
        <div class="footer">
          <a> </a>
          <a> </a>
        </div>
      </div>
      <div class="research-post--skeleton--item">
        <div class="post-title-skeleton">
          <p></p>
        </div>
        <div class="post-sub-title-skeleton">
          <p></p>
        </div>
        <div class="footer">
          <a> </a>
          <a> </a>
        </div>
      </div>
    </template>
    <Modal
      v-model="likedUserModal"
      title="People Who Liked"
      :mask-closable="true"
      :closable="true"
    >
      <div class="comment-liked" v-for="user in likedUser">
                    <img :src="`${http + user.image}`" alt="img" />
        <nuxt-link :to="`/profile/${user.user_slug}/overview`">
          {{ user.name }}
        </nuxt-link>
      </div>
      <div slot="footer"></div>
    </Modal>
    <Modal v-model="visible">
      <img :src="imgName" style="width: 100%" />
      <div slot="footer"></div>
    </Modal>
  </div>
</template>

<script>
import { mapGetters } from "vuex";
import {
  Hooper,
  Slide,
  Progress as HooperProgress,
  Pagination as HooperPagination,
  Navigation as HooperNavigation,
} from "hooper";
import "hooper/dist/hooper.css";
export default {
  middleware: "auth",

  components: {
    Hooper,
    Slide,
    HooperProgress,
    HooperPagination,
    HooperNavigation,
  },
  data() {
    return {
      hooperImage: {
        commentsToShow: 1,
        centerMode: false,
        breakpoints: {
          768: {
            centerMode: false,
            itemsToShow: 2,
          },
        },
      },
      limit: 3,
      page: 1,
      loadMoreLoading: false,
      noPostRemaining: false,
      showProjectForm: false,
      loading: false,
      likedUserModal: false,
      isAttachmentLoading: false,
      visible: false,
      imgName: "",
      errors: [],
      users: [],
      likedUser: [],
      user_id: -1,
      user_slug: "",
      route_slug: this.$route.params.slug,
      data: {
        type: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        affiliation: "",
        images: [],
        pdf: "",
        start_date: "",
        end_date: "",
        iconImage: "",
      },
      editData: {
        id: "",
        user_id: "",
        type: "",
        title: "",
        author_id: [],
        attachment: "",
        affiliation: "",
        abstract: "",
        start_date: "",
        end_date: "",
        url: "",
        images: [],
        iconImage: "",
      },
      imageName: [],
      edit_id: "",
      index: "",
      attachmentName: "",
      isEditingItem: false,
      isDeletingAll: false,
      isIconImageNew: false,
      iconImageName: "",
      isAdd: false,
      deleting: false,
      socket: null,
      http: this.$config.IMAGE_URL,
    };
  },
  computed: {
    ...mapGetters({
      posts: "getUserProject",
      isLoading: "getGlobalPostLoading",
    }),
  },
  methods: {
    async deleteAttachment() {
      let attachment = this.attachmentName;
      // this.$refs.upload.clearFiles();
      this.attachmentName = "";
      this.data.attachment = "";
      this.editData.attachment = "";

      const res = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      if (res.status != 200) {
        if (edit_id != "") {
          this.editData.attachment = attachment;
        } else {
          this.data.attachment = attachment;
        }
        this.swr();
      }
    },
    async handleRemove(file, fileList) {
      let attachment = this.attachmentName;

      this.attachmentName = "";
      this.data.attachment = "";
      this.editData.attachment = "";

      const res = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      if (res.status != 200) {
        if (edit_id != "") {
          this.editData.attachment = attachment;
        } else {
          this.data.attachment = attachment;
        }
        this.swr();
      }
    },
    handleImageSuccess(res, file) {
      // this.iconImageName = `${res}`;
      this.imageName.push(`${res}`);

      res = `${res}`;
      if (this.isEditingItem) {
        console.log("inside");
        return this.editData.images.push(res);
      }
      console.log(res);
      // this.data.iconImage = res;
      this.data.images.push(res);
    },
    async deleteImage(index) {
      let image;
      if (this.isEditingItem) {
        // for editing....
        console.log(this.imageName);

        image = this.editData.images[index];
        this.editData.images.splice(index, 1);

        // this.$refs.editDataUploads.clearFiles();
      } else {
        // image = this.iconImageName;

        image = this.data.images[index];
        this.data.images.splice(index, 1);
      }
      const res = await this.callApi("post", "/api/delete_image", {
        imageName: image,
      });
      // this.imageName.splice(index, 1);
      if (res.status != 200) {
        this.data.iconImage = image;
        this.swr();
      }
    },
    async handleSuccess(res, file) {
      let attachment = this.attachmentName;
      this.isAttachmentLoading = true;
      const res1 = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      console.log(this.data.attachment);
      if (this.edit_id != "") {
        this.editData.attachment = `${res}`;
        this.$refs.uploadAttachmentEdit.clearFiles();
      } else {
        this.data.attachment = `${res}`;
        this.$refs.uploadAttachment.clearFiles();
      }
      this.attachmentName = `${res}`;
      this.isAttachmentLoading = false;
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
    async showForm() {
      this.loading = true;

      this.getAuthors(this.authUser.name);
      this.data.author_id.push(this.authUser.id);
      this.showProjectForm = true;
      this.loading = false;
    },
    async reset() {
      this.showProjectForm = false;
      this.edit_id = "";
      this.index = "";
      this.user_slug = this.$route.params.slug;
      this.attachmentName = "";
      this.data = {
        type: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        pdf: "",
        start_date: "",
        end_date: "",
      };
      this.editData = {
        type: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        pdf: "",
        start_date: "",
        end_date: "",
      };
      this.$store.commit("setGlobalPostLoading", true);

      const res = await this.callApi(
        "get",
        `/api/get_user_project/${this.user_slug}?limit=${this.limit}`
      );
      if (res.status == 200) {
        this.$store.commit("setUserProject", res.data.data);
        // this.$store.commit("setGlobalPostLoading", false);
      }
      // else {
      //   this.swr();
      // }
      this.$store.commit("setGlobalPostLoading", false);
    },
    async save() {
      // if (this.data.project_name.trim() == "")
      //     return this.e("Project Name is required");
      // if (this.data.project_type.trim() == "")
      //     return this.e("Project type is required");
      // if (this.data.start_date.trim() == "")
      //     return this.e("Start date is required");
      this.data.type = "Project";
      this.loading = true;

      const res = await this.callApi("post", `/api/save_post`, this.data);
      if (res.status === 200) {
        this.s(res.data.msg);
        this.reset();
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            this.errors = res.data.errors;
          }
        } else {
          this.swr();
        }
      }
      this.loading = false;
    },
    async showEdit(index) {
      this.editData = {
        type: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        pdf: "",
        start_date: "",
        end_date: "",
      };
      if (this.posts[index].id) {
        this.index = index;
        this.edit_id = this.posts[index].id;
        this.editData.id = this.posts[index].id;
        this.editData.user_id = this.posts[index].user_id;
        this.editData.title = this.posts[index].title;
        this.editData.type = this.posts[index].type;
        this.editData.affiliation = this.posts[index].affiliation;
        this.editData.start_date = this.posts[index].edit_start_date;
        this.editData.end_date = this.posts[index].edit_end_date;
        this.editData.url = this.posts[index].url;
        this.editData.abstract = this.posts[index].abstract;
        this.editData.attachment = this.posts[index].attachment;
        this.attachmentName = this.editData.attachment;

        this.users = this.posts[index].authors;

        for (let t of this.posts[index].authors) {
          console.log(t.name);
          this.editData.author_id.push(parseInt(t.id));
        }
        for (let t of this.posts[index].images) {
          this.editData.images.push(t.image_name);
          this.imageName.push(t.image_name);
        }
        this.$nextTick(() => {
          if (this.$refs["projectName" + this.posts[index].id]) {
            this.$refs["projectName" + this.posts[index].id][0].focus();
          }
        });
        this.isEditingItem = true;
      }
    },
    async update() {
      // if (this.data.project_name.trim() == "")
      //     return this.e("Project Name is required");
      // if (this.data.project_type.trim() == "")
      //     return this.e("Project type is required");
      // if (this.data.start_date.trim() == "")
      //     return this.e("Start date is required");
      var startDate = this.editData.start_date.toLocaleString("en-us", {
        month: "short",
        year: "numeric",
      });
      var endDate = this.editData.end_date.toLocaleString("en-us", {
        month: "short",
        year: "numeric",
      });
      this.loading = true;
      const res = await this.callApi("post", "/api/update_post", this.editData);
      if (res.status === 200) {
        // this.reset();
        this.errors = [];
        this.posts[this.index].id = this.editData.id;
        this.posts[this.index].user_id = this.editData.user_id;
        this.posts[this.index].title = this.editData.title;
        this.posts[this.index].type = this.editData.type;
        this.posts[this.index].start_date = startDate;
        this.posts[this.index].end_date = endDate;
        this.posts[this.index].affiliation = this.editData.affiliation;
        this.posts[this.index].url = this.editData.url;
        this.posts[this.index].attachment = this.editData.attachment;
        this.posts[this.index].abstract = this.editData.abstract;

        this.reset();
        this.s("Project Updated!!");
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
      this.loading = false;
    },
    async deletePost() {
      this.deleting = true;
      this.deleteAttachment();
      for (let t of this.editData.images) {
        const res = await this.callApi("post", "/api/delete_image", {
          imageName: t,
        });
      }
      const res = await this.callApi(
        "post",
        `/api/delete_post?id=${this.editData.id}`
      );
      if (res.status === 200) {
        this.s(res.data.msg);
        // this.reset();
        this.edit_id = "";
        this.index = "";
        this.posts.splice(this.index, 1);
      } else {
        this.swr();
      }
      this.deleting = false;
    },

    async like(index) {
      if (this.posts[index].user_id != this.authUser.id) {
        let obj = {
          id: this.posts[index].id,
        };
        this.id = this.posts[index].id;
        console.log(this.id);
        if (this.posts[index].authUserLike == "no") {
          this.posts[index].like_count += 1;
          this.posts[index].authUserLike = "yes";
        } else {
          this.posts[index].like_count -= 1;
          this.posts[index].authUserLike = "no";
        }
        let notificationObj = {
          id: this.posts[index].user_id,
        };
        const res = await this.callApi("post", "/api/like", obj);
        this.socket.emit("notification", notificationObj);
      } else {
        this.i("You can't like your own post!!");
      }
    },

    async getLikedUser(index) {
      let obj = {
        id: this.posts[index].id,
      };
      console.log(this.posts[index].id);
      const res = await this.callApi(
        "get",
        `/api/get_liked_user?id=${this.posts[index].id}`
      );
      if (res.status == 200) {
        this.likedUser = res.data.data;
        this.likedUserModal = true;
      } else {
        this.swr();
      }
    },
    async getAuthors(query) {
      console.log(query);
      const response = await this.callApi(
        "get",
        `/api/search?keyword=${query}`
      );
      if (response.status == 200) {
        this.users = response.data;
      }
    },
    async loadMore(more) {
      console.log("Load more is calling! length", this.posts.length);
      this.user_slug = this.$route.params.slug;

      if (this.noPostRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_user_project/${this.user_slug}?limit=${this.limit}`
      );
      if (res.status == 200) {
        let prevLength = this.posts.length;
        if (this.posts.length == res.data.data.length) {
          this.noPostRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.$store.commit("pushUserProject", d);
          }
        }
      }
      this.loadMoreLoading = false;
      console.log("Load more is finished! length", this.posts.length);
    },
  },

  async created() {
    this.page = this.$route.query.page ? this.$route.query.page : 1;
    this.$store.commit("setGlobalPostLoading", true);
    this.user_slug = this.$route.params.slug;

    const res = await this.callApi(
      "get",
      `/api/get_user_project/${this.user_slug}?limit=${this.limit}`
    );
    if (res.status == 200) {
      this.$store.commit("setUserProject", res.data.data);
      // this.$store.commit("setGlobalPostLoading", false);
    }
    // else {
    //   this.swr();
    // }
    this.$store.commit("setGlobalPostLoading", false);
  },

  mounted() {
    this.socket = io("http://localhost:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
    // document.addEventListener("click", this.hideSearchbar);
    window.onscroll = () => {
      this.bottomOfWindow =
        window.pageYOffset + window.innerHeight >
        document.body.scrollHeight - 100;

      if (this.bottomOfWindow) {
        if (!this.loadMoreLoading) {
          this.loadMore(3);
        }
      }
    };
  },

  watch: {
    "$route.fullPath": function (newVal, oldVal) {
      // watch it
      console.log("Prop changed: ", newVal, " | was: ", oldVal);
      window.scrollTo(0, 0);

      this.page = this.$route.query.page ? this.$route.query.page : 1;

      this.filterPosts();
    },
  },
};
</script>

<style scoped>
.card-header-border {
  border-bottom: 1px solid #34c5d9;
}
p {
  color: #333;
}
.profile-info-skeleton h5 {
  width: 60%;
  height: 24px;
  display: block;
  background-color: #c0c0c0;
  margin: 0.25rem;
}
.profile-info-skeleton p {
  width: 95%;
  height: 16px;
  margin: 0.25rem;
  background-color: #c0c0c0;
}
</style>
<style lang="scss">
.slide {
  &-enter {
    overflow: hidden;
    max-height: 0;
    &-to {
      max-height: 500px;
      overflow: hidden;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: ease-in;
      -webkit-transition-timing-function: ease-in;
      -o-transition-timing-function: ease-in;
      transition-timing-function: ease-in;
    }
  }
  &-leave {
    @extend .slide-enter-to;
    &-to {
      @extend .slide-enter;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -webkit-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -o-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
    }
  }
}
</style>
