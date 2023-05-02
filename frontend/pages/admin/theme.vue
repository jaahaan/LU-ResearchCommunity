<template>
  <div class="connection--item mt-40">
    <div>
      <h5 class="post-title">
        Theme
        <a class="main-btn float-end" v-if="!isEdit" @click="showEdit">
          Edit Theme
        </a>
      </h5>
      <section class="container">
        <div class="teacher-section">
          <div class="teacher-section--table">
            <div v-if="loading" class="loader-lg">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
            </div>
            <Table
              v-else
              class="table table-bordered"
              :loading="loading"
              :columns="columns1"
              border
              :data="data1"
            >
              <template slot-scope="{ row, index }" slot="color">
                <div v-if="isEdit">
                  <input
                    style="width: 120px"
                    type="color"
                    v-model="formValue[index].value"
                  />
                </div>
                <div v-else class="d-flex justify-content-center">
                  <td
                    :style="`width: 120px; height: 25px; border:1px solid; background: ${row.value};`"
                  ></td>
                </div>
              </template>
            </Table>
          </div>
        </div>
      </section>
      <h5 class="post-title">
        <div></div>
        <div>
          <a class="main-btn float-end" v-if="isEdit" @click="saveChanges">
            Save Theme
          </a>
          <a class="main-btn float-end" v-if="isEdit" @click="cancel">
            Cancel
          </a>
        </div>
      </h5>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      loading: false,
      listMethod: true,
      isCollapsed: false,
      visible: false,
      imgName: "",
      opening: null,
      isEdit: false,
      id: "",
      editObj: {
        index: -1,
        item: null,
      },

      columns1: [
        {
          title: "Name",
          key: "name",
        },
        {
          title: "Value",
          slot: "color",
        },
      ],
      data1: [
        {
          name: "Theme Color",
          value: "-----",
        },
        {
          name: "Background Color",
          value: "----",
        },
        {
          name: "Font Color",
          value: "-----",
        },
        {
          name: "Font Hover Color",
          value: "-----",
        },
      ],
      formValue: [{ value: "" }, { value: "" }, { value: "" }, { value: "" }],
    };
  },

  methods: {
    showEdit(id) {
      this.formValue[0].value = this.data1[0].value;
      this.formValue[1].value = this.data1[1].value;
      this.formValue[2].value = this.data1[2].value;
      this.formValue[3].value = this.data1[3].value;
      this.isEdit = true;
    },
    cancel() {
      this.isEdit = false;
    },
    async saveChanges() {
      let ob = {
        id: this.id,
        theme_colour: this.formValue[0].value,
        background_color: this.formValue[1].value,
        font_color: this.formValue[2].value,
        font_hover_color: this.formValue[3].value,
      };
      const response = await this.callApi("put", "/api/themeSettingUpdate", ob);
      if (response.status == 200) {
        this.data1[0].value = this.formValue[0].value;
        this.data1[1].value = this.formValue[1].value;
        this.data1[2].value = this.formValue[2].value;
        this.data1[3].value = this.formValue[3].value;
        this.isEdit = false;

        location.reload();
      } else if (response.status == 422) {
        for (let x in response.data) {
          this.e(response.data[x]);
        }
        this.isEdit = false;
      } else this.swr();
      this.isEdit = false;
    },
    async getThemeSetting() {
      this.loading = true;
      const response = await this.callApi("get", "/api/getThemeSetting");
      if (response.status == 200) {
        this.id = response.data.id;
        this.data1[0].value = response.data.theme_colour;
        this.data1[1].value = response.data.background_color;
        this.data1[2].value = response.data.font_color;
        this.data1[3].value = response.data.font_hover_color;
        this.loading = false;
      } else this.e("Oops!", "Something went wrong, please try again!");
    },
  },
  async created() {
    await this.getThemeSetting();
  },
};
</script>
