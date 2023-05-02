<template>
  <div>
    <!--****** Add Research box ******-->

    <template
      v-if="isLoading == false && showResearchForm == false && posts == ''"
    >
      <div v-if="authUser.slug == route_slug">
        <div class="_card" v-on:click="showForm()">
          <button>
            <h1>
              No Research Found.<br />
              <i class="lni lni-folder"></i> Add Your Research
            </h1>
          </button>
        </div>
      </div>
      <div v-else>
        <div class="_card"><h1>No Research Found</h1></div>
      </div>
    </template>

    <!--****** Add Research form ******-->
    <template v-if="showResearchForm == true">
      <div class="research-post--item">
        <h5 class="post-title">
          <div v-if="data.type == ''">Add Research</div>
          <div v-else>Add {{ data.type }}</div>

          <div class="btn-edit text-danger" @click="reset">
            <i class="fa-solid fa-xmark"></i>
          </div>
        </h5>
        <Form label-position="top">
          <FormItem label="Type *">
            <Select v-model="data.type" placeholder="Select Type">
              <Option value="Article">Article</Option>
              <Option value="Conference Paper">Conference Paper</Option>
              <Option value="Data">Data</Option>
              <Option value="Research">Research</Option>
              <Option value="Presentation">Presentation</Option>
              <Option value="Preprint">Preprint</Option>
              <Option value="Poster">Poster</Option>
              <Option value="Note">Note</Option>
            </Select>
            <span class="text-danger" v-if="errors.type">{{
              errors.type[0]
            }}</span>
          </FormItem>

          <div v-if="data.type == 'Conference Paper'">
            <FormItem
              label="Conference *"
              v-if="data.type == 'Conference Paper'"
            >
              <Input
                type="text"
                v-model="data.conference"
                placeholder="Conference"
              />
              <span class="text-danger" v-if="errors.conference">{{
                errors.conference[0]
              }}</span>
            </FormItem>
            <FormItem
              label="Publication Date"
              v-if="data.type == 'Conference Paper'"
            >
              <DatePicker
                type="month"
                v-model="data.publication_date"
                placeholder="Publication Date"
                class="d-block"
              ></DatePicker>
              <span class="text-danger" v-if="errors.start_date">{{
                errors.start_date[0]
              }}</span>
            </FormItem>
          </div>
          <FormItem label="Title *">
            <Input type="text" v-model="data.title" placeholder="Title" />
            <span class="text-danger" v-if="errors.title">{{
              errors.title[0]
            }}</span>
          </FormItem>

          <FormItem label="Abstract">
            <textarea
              class="form-control form-outline"
              v-model="data.abstract"
              rows="4"
            ></textarea>
            <span class="text-danger" v-if="errors.abstract">{{
              errors.abstract[0]
            }}</span>
          </FormItem>

          <FormItem label="Authors">
            <Select
              filterable
              multiple
              placeholder="Select Authors"
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
            <Input
              type="text"
              placeholder="Affiliation"
              v-model="data.affiliation"
            />
            <span class="text-danger" v-if="errors.affiliation">{{
              errors.affiliation[0]
            }}</span>
          </FormItem>
          <FormItem label="URL">
            <Input type="url" v-model="data.url" placeholder="URL" />
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
              :max-size="20048"
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
            <Button class="main-btn main-btn__border" @click="reset">
              Cancel</Button
            >
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

    <!--**** Researches ****-->
    <template
      v-if="posts != '' && isLoading == false && showResearchForm == false"
    >
      <div>
        <div>
          <div class="section-header">
            <div>
              <h3>Research Items</h3>
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
              <div v-if="editData.type == ''">Edit Research</div>
              <div v-else>Edit {{ editData.type }}</div>

              <div class="btn-edit text-danger" @click="reset">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form label-position="top">
              <FormItem label="Research Type *">
                <Select v-model="editData.type" placeholder="Select Type">
                  <Option value="Article">Article</Option>
                  <Option value="Conference Paper">Conference Paper</Option>
                  <Option value="Data">Data</Option>
                  <Option value="Research">Research</Option>
                  <Option value="Presentation">Presentation</Option>
                  <Option value="Preprint">Preprint</Option>
                  <Option value="Poster">Poster</Option>
                  <Option value="Note">Note</Option>
                </Select>
                <span class="text-danger" v-if="errors.type">{{
                  errors.type[0]
                }}</span>
              </FormItem>
              <div v-if="editData.type == 'Conference Paper'">
                <FormItem label="Conference *">
                  <Input
                    type="text"
                    v-model="editData.conference"
                    placeholder="Conference"
                  />
                  <span class="text-danger" v-if="errors.conference">{{
                    errors.conference[0]
                  }}</span>
                </FormItem>
                <FormItem label="Publication Date">
                  <DatePicker
                    type="month"
                    v-model="editData.publication_date"
                    placeholder="Publication Date"
                    class="d-block"
                  ></DatePicker>
                  <span class="text-danger" v-if="errors.start_date">{{
                    errors.start_date[0]
                  }}</span>
                </FormItem>
              </div>
              <FormItem label="Title *">
                <Input
                  type="text"
                  v-model="editData.title"
                  placeholder="Research Title"
                />
                <span class="text-danger" v-if="errors.title">{{
                  errors.title[0]
                }}</span>
              </FormItem>

              <FormItem label="Abstract">
                <Input
                  v-model="editData.abstract"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 5 }"
                  placeholder="Write abstract..."
                ></Input>
                <span class="text-danger" v-if="errors.abstract">{{
                  errors.abstract[0]
                }}</span>
              </FormItem>
              <FormItem label="Authors">
                <Select
                  filterable
                  multiple
                  placeholder="Select Authors"
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
              <FormItem label="URL">
                <Input type="url" v-model="editData.url" placeholder="URL" />
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
                v-if="authUser.slug == route_slug && edit_id == ''"
                @click="showEdit(index)"
              >
                <i class="lni lni-pencil"></i>
              </div>
            </h5>

            <!-- <div class="post-sub-title">
            <p v-if="research.end_date">
              {{ research.start_date }} -
              {{ research.end_date }}
            </p>
            <p v-else>{{ research.start_date }} - Ongoing</p>
          </div> -->
            <div class="post-sub-title" v-if="research.affiliation">
              <p>
                <i class="fa-solid fa-graduation-cap"></i> Associated with
                {{ research.affiliation }}
              </p>
            </div>

            <p class="my-3">
              <nuxt-link
                :to="`/description/${research.slug}/overview`"
                class="py-2 px-4 alert alert-secondary text-center"
              >
                {{ research.type }}</nuxt-link
              >
            </p>
            <div class="post-sub-title" v-if="research.conference">
              <div>
                <p>
                  {{ research.publication_date }}
                </p>
                <p>Conference: {{ research.conference }}</p>
              </div>
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
              {{ research.abstract.substring(0, 90) }}
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
      </div>
    </template>
    <div v-if="isLoading == false">
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
    <!--**** loader ****-->
    <div v-if="isLoading == true">
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
    </div>
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
      visible: false,
      imgName: "",
      deleting: false,
      loading: false,
      limit: 3,
      page: 1,
      loadMoreLoading: false,
      noPostRemaining: false,
      showResearchForm: false,
      likedUserModal: false,
      // isLoading: true,
      loading1: false,
      errors: [],
      users: [],
      likedUser: [],
      user_id: -1,
      user_slug: "",
      route_slug: this.$route.params.slug,
      data: {
        type: "",
        conference: "",
        conference_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        pdf: "",
        start_date: "",
        end_date: "",
        iconImage: "",
      },
      editData: {
        user_id: "",
        type: "",
        conference: "",
        conference_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        start_date: "",
        end_date: "",
        url: "",
        images: [],
        iconImage: "",
        id: "",
        start_date: "",
        end_date: "",
        index: "",
      },
      edit_id: "",
      index: "",
      isEditingItem: false,
      attachmentName: "",
      isAttachmentLoading: false,
      isIconImageNew: false,
      iconImageName: "",
      imageName: [],
      http: this.$config.IMAGE_URL,
      socket: null,
    };
  },

  computed: {
    ...mapGetters({
      posts: "getUserResearch",
      isLoading: "getGlobalPostLoading",
    }),
  },
  methods: {
    handleView(item, index) {
      this.imgName = this.http + item;
      this.index = index;
      this.visible = true;
    },
    clearErrorMessage() {
      this.errors = [];
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
      } else {
        image = this.data.images[index];
        this.data.images.splice(index, 1);
      }
      const res = await this.callApi("post", "/api/delete_image", {
        imageName: image,
      });
      if (res.status != 200) {
        this.data.iconImage = image;
        this.swr();
      }
    },
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
    async handleSuccess(res, file) {
      let attachment = this.attachmentName;
      this.isAttachmentLoading = true;
      const res1 = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      console.log(this.data.attachment);
      // this.data.attachment = `${res}`;
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
    async showForm() {
      this.loading = true;

      this.getAuthors(this.authUser.name);
      this.data.author_id.push(this.authUser.id);
      this.showResearchForm = true;
      this.loading = false;
    },
    async reset() {
      this.showResearchForm = false;
      this.edit_id = "";
      this.index = "";
      this.attachmentName = "";
      this.user_slug = this.$route.params.slug;
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
      // this.$store.commit("setGlobalPostLoading", true);

      const res = await this.callApi(
        "get",
        `/api/get_user_research?slug=${this.user_slug}&limit=${this.limit}`
      );
      if (res.status == 200) {
        this.$store.commit("setUserResearch", res.data.data);
        // this.$store.commit("setGlobalPostLoading", false);
      }
      // else {
      //   this.swr();
      // }
      // this.$store.commit("setGlobalPostLoading", false);
    },
    async save() {
      // if (this.data.project_name.trim() == "")
      //     return this.e("Project Name is required");
      // if (this.data.project_type.trim() == "")
      //     return this.e("Project type is required");
      // if (this.data.start_date.trim() == "")
      //     return this.e("Start date is required");

      console.log(this.user_id);
      this.loading = true;

      const res = await this.callApi("post", `/api/save_post`, this.data);
      if (res.status === 200) {
        this.s(res.data.msg);
        // this.msg = res.data.msg;
        this.reset();
        this.clearErrorMessage();
      } else {
        if (res.status == 422) {
          console.log(this.$route.params.id);

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
        this.editData.conference = this.posts[index].conference;
        this.editData.affiliation = this.posts[index].affiliation;
        this.editData.attachment = this.posts[index].attachment;
        this.attachmentName = this.editData.attachment;
        this.editData.publication_date =
          this.posts[index].edit_publication_date;
        this.editData.url = this.posts[index].url;
        this.editData.abstract = this.posts[index].abstract;
        // const response = await this.callApi("get", `/api/get_user`);
        // if (response.status == 200) {
        //   this.users = response.data;
        // }
        this.users = this.posts[index].authors;
        for (let t of this.posts[index].authors) {
          console.log(t.name);

          this.editData.author_id.push(parseInt(t.id));
        }
        for (let t of this.posts[index].images) {
          this.editData.images.push(t.image_name);
          this.imageName.push(t.image_name);
        }
        this.isEditingItem = true;
        this.$nextTick(() => {
          if (this.$refs["projectName" + this.posts[index].id]) {
            this.$refs["projectName" + this.posts[index].id][0].focus();
          }
        });
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
        this.s("Research Updated!!");
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
        `/api/get_user_research?slug=${this.user_slug}&limit=${this.limit}`
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
            this.$store.commit("pushUserResearch", d);
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
      `/api/get_user_research?slug=${this.user_slug}&limit=${this.limit}`
    );
    if (res.status == 200) {
      this.$store.commit("setUserResearch", res.data.data);
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
    },
  },
};
</script>
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
