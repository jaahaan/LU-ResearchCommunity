<template>
  <div class="research-people">
    <div class="research-post--item">
      <h5 class="post-title">Connections</h5>
      <ul>
        <li v-for="(user, index) in peopleYouMayKnow">
          <div class="content">
            <img :src="user.image" alt="img" />
            <div>
              <nuxt-link :to="`/profile/${user.slug}/overview`">
                {{ user.name }}
              </nuxt-link>
              <p>
                {{ user.designation }}<span class="dot">•</span
                >{{ user.department.department_name }}
              </p>
            </div>
          </div>
          <button
            class="main-btn main-btn__bg"
            v-if="user.status == 'pending'"
            @click="ignoreConnection(index)"
          >
            <i class="fa-solid fa-clock-rotate-left"></i>
            Pending
          </button>
          <button
            class="main-btn main-btn__border"
            @click="connect(index)"
            v-else-if="user.status == 'connect'"
          >
            <i class="fa-solid fa-user-plus"></i>
            Connect
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>

<script>
export default {
  middleware: "auth",

  components: {},
  data() {
    return {
      showResearchForm: false,
      isLoading: true,
      errors: [],
      researches: [],
      users: [],
      user_slug: -1,
      route_id: this.$route.params.id,
      config: {},
      initData: null,
      data: {
        jsonData: null,
        author_id: [],
      },
      articleHTML: "",

      isEditingItem: false,
      attachmentName: "",
    };
  },
  methods: {
    showForm() {
      this.showResearchForm = true;
    },
    async reset() {
      this.showResearchForm = false;
      this.editData.id = "";
      this.user_slug = this.$route.params.slug;

      const res = await this.callApi("get", `/api/get_post/${this.user_slug}`);
      if (res.status == 200) {
        this.projects = res.data;
        this.errors = [];
      } else {
        this.swr();
      }

      this.isLoading = false;
    },
    async onSave(response) {
      var data = response;
      await this.outputHtml(data.blocks);
      this.data.post = this.articleHTML;
      this.data.jsonData = JSON.stringify(data);
      if (this.data.post.trim() == "") return this.e("Post is required");
      if (this.data.title.trim() == "") return this.e("Title is required");
      if (this.data.post_excerpt.trim() == "")
        return this.e("Post exerpt is required");
      if (this.data.metaDescription.trim() == "")
        return this.e("Meta description is required");
      if (!this.data.tag_id.length) return this.e("Tag is required");
      if (!this.data.category_id.length) return this.e("Category is required");
      this.isCreating = true;
      const res = await this.callApi("post", "app/create-blog", this.data);
      if (res.status === 200) {
        this.s("Blog has been created successfully!");
        // redirect...
        this.$router.push("/blogs");
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            this.e(res.data.errors[i][0]);
          }
        } else {
          this.swr();
        }
      }
      this.isCreating = false;
    },

    async save() {
      this.$refs.editor.save();
    },
    outputHtml(articleObj) {
      articleObj.map((obj) => {
        switch (obj.type) {
          case "paragraph":
            this.articleHTML += this.makeParagraph(obj);
            break;
          case "image":
            this.articleHTML += this.makeImage(obj);
            break;
          case "header":
            this.articleHTML += this.makeHeader(obj);
            break;
          case "raw":
            this.articleHTML += `<div class="ce-block">
					<div class="ce-block__content">
					<div class="ce-code">
						<code>${obj.data.html}</code>
					</div>
					</div>
				</div>\n`;
            break;
          case "code":
            this.articleHTML += this.makeCode(obj);
            break;
          case "list":
            this.articleHTML += this.makeList(obj);
            break;
          case "quote":
            this.articleHTML += this.makeQuote(obj);
            break;
          case "warning":
            this.articleHTML += this.makeWarning(obj);
            break;
          case "checklist":
            this.articleHTML += this.makeChecklist(obj);
            break;
          case "embed":
            this.articleHTML += this.makeEmbed(obj);
            break;
          case "delimeter":
            this.articleHTML += this.makeDelimeter(obj);
            break;
          default:
            return "";
        }
      });
    },

    async save() {
      // if (this.data.project_name.trim() == "")
      //     return this.e("Project Name is required");
      // if (this.data.project_type.trim() == "")
      //     return this.e("Project type is required");
      // if (this.data.start_date.trim() == "")
      //     return this.e("Start date is required");
      this.user_slug = this.$route.params.slug;
      console.log(this.user_slug);
      const res = await this.callApi(
        "post",
        `/api/save_post/${this.user_slug}`,
        this.data
      );
      this.isLoading = true;
      if (res.status === 200) {
        this.s(res.data.msg);
        // this.msg = res.data.msg;
        this.data.type = "";
        this.data.title = "";
        this.data.author_id = "";
        this.data.attachment = "";
        this.data.abstract = "";
        this.data.start_date = "";
        this.data.end_date = "";
        this.data.url = "";
        this.attachmentName = "";
        this.reset();
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
      this.isLoading = false;
    },
  },
  async created() {
    // this.token = window.Laravel.csrfToken;
    this.user_slug = this.$route.params.slug;

    const res = await this.callApi("get", `/api/get_post/${this.user_slug}`);
    const resuser = await this.callApi("get", `/api/get_all_user`);
    if (resuser.status == 200) {
      this.users = resuser.data;
    } else {
      this.swr();
    }

    this.isLoading = false;
  },
};
</script>

<style></style>
