<template>
  <div>
    <div v-if="isLoading == false">
      <div class="mb-4" v-if="authUser.slug == this.$route.params.slug">
        <button class="main-btn m-0 w-100" v-on:click="showSidebar()">
          <i class="fa-solid fa-plus"></i> Add New
        </button>
      </div>
      <div
        class="mb-2 p-3"
        v-if="
          profileInfo.about == null &&
          profileInfo.user_skills == '' &&
          educationInfo == ''
        "
      >
        <div class="_card"><h1>No Information Found</h1></div>
      </div>
      <!--**** about-section starts ****-->
      <!-- about edit -->
      <div>
        <template v-if="about_id">
          <div class="research-post--item">
            <h5 class="post-title">
              <div>Edit About</div>
              <div class="btn-edit text-danger" @click="reset()">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <textarea
              class="form-control"
              v-model="editData.about"
              rows="4"
              placeholder="Write About You..."
              :ref="`about${profileInfo.about}`"
            ></textarea>
            <div class="footer">
              <div></div>
              <div>
                <Button
                  class="main-btn main-btn__bg"
                  @click="deleteAbout"
                  :disabled="deleting"
                  :loading="deleting"
                  ><i class="fa-solid fa-floppy-disk"></i>
                  {{ deleting ? "Deleting.." : "Delete" }}</Button
                >
                <Button
                  class="main-btn main-btn__bg"
                  @click="updateAbout"
                  :disabled="isAdding"
                  :loading="isAdding"
                  ><i class="fa-solid fa-floppy-disk"></i>
                  {{ isAdding ? "Saving.." : "Save" }}</Button
                >
              </div>
            </div>
          </div>
        </template>

        <!-- about -->
        <template v-else>
          <div class="research-post--item" v-if="profileInfo.about">
            <h5 class="post-title">
              <div>About</div>
              <div
                v-if="authUser.slug == this.$route.params.slug"
                class="btn-edit"
                @click="editAbout"
              >
                <i class="lni lni-pencil"></i>
              </div>
            </h5>
            <p>
              {{ profileInfo.about.substring(0, 90) }}
            </p>
          </div>
        </template>
      </div>
      <!--**** about-section ends ****-->

      <!--**** education-section starts ****-->

      <template>
        <div class="research-post--item" v-if="educationInfo != ''">
          <h5 class="post-title">
            <div>Education</div>
            <div
              v-if="authUser.slug == this.$route.params.slug && !edit_education"
              class="btn-edit"
              @click="showEditAllEducation"
            >
              <i class="lni lni-pencil"></i>
            </div>

            <div @click="cancelEditEducation" v-else-if="edit_education">
              <a class="main-btn main-btn__border">Finish editing</a>
            </div>
          </h5>
          <div
            v-for="(education, index) in educationInfo"
            :key="index"
            class="education__section"
          >
            <template v-if="editEducationData.id == education.id">
              <div class="research-post--item">
                <h5 class="post-title">
                  <div>
                    Edit <b>{{ editEducationData.institute }}</b>
                  </div>
                  <div class="btn-edit" @click="cancelEducationModal">
                    <i class="fa-solid fa-xmark"></i>
                  </div>
                </h5>
                <Form label-position="top">
                  <FormItem label="Institute *">
                    <Input
                      v-model="editEducationData.institute"
                      placeholder="Ex: Leading University"
                      :ref="`institute${education.id}`"
                    ></Input>
                    <span class="text-danger" v-if="errors.institute">{{
                      errors.institute[0]
                    }}</span>
                  </FormItem>
                  <FormItem label="Degree">
                    <Input
                      v-model="editEducationData.degree"
                      placeholder="Ex: Bachelor's"
                    ></Input>
                    <span class="text-danger" v-if="errors.degree">{{
                      errors.degree[0]
                    }}</span>
                  </FormItem>
                  <FormItem label="Field of study">
                    <Input
                      v-model="editEducationData.fieldOfStudy"
                      placeholder="Ex: Computer Science"
                    ></Input>
                    <span class="text-danger" v-if="errors.fieldOfStudy">{{
                      errors.fieldOfStudy[0]
                    }}</span>
                  </FormItem>

                  <div class="row">
                    <div class="col-6">
                      <FormItem label="Start Date">
                        <DatePicker
                          type="month"
                          v-model="editEducationData.start_date"
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
                          v-model="editEducationData.end_date"
                          placeholder="End Date (or expected)"
                          class="d-block"
                        ></DatePicker>
                        <span class="text-danger" v-if="errors.end_date">{{
                          errors.end_date[0]
                        }}</span>
                      </FormItem>
                    </div>
                  </div>

                  <FormItem label="Grade">
                    <Input
                      v-model="editEducationData.grade"
                      placeholder="Grade"
                    ></Input>
                    <span class="text-danger" v-if="errors.grade">{{
                      errors.grade[0]
                    }}</span>
                  </FormItem>
                  <FormItem label="Description">
                    <Input
                      v-model="editEducationData.activities"
                      type="textarea"
                      :autosize="{ minRows: 2, maxRows: 5 }"
                      placeholder="Write description..."
                    ></Input>
                    <span class="text-danger" v-if="errors.activities">{{
                      errors.activities[0]
                    }}</span>
                  </FormItem>
                </Form>

                <div class="footer">
                  <div></div>
                  <div>
                    <button
                      class="main-btn main-btn__border"
                      @click="cancelEducationModal"
                    >
                      Cancel
                    </button>
                    <button
                      class="main-btn main-btn__border"
                      @click="updateEducation(index)"
                    >
                      <i class="fa-solid fa-floppy-disk"></i> Save
                    </button>
                  </div>
                </div>
              </div>
            </template>
            <template v-else>
              <div class="title">
                <h6>{{ education.institute }}</h6>
                <div v-if="edit_education">
                  <i
                    class="lni lni-pencil"
                    @click="showEditSingleEducation(index)"
                  ></i>
                  <i
                    class="lni lni-trash-can"
                    @click="showEducationRemove(index)"
                  ></i>
                </div>
              </div>
              <p class="sub-title">
                {{ education.degree }} in {{ education.fieldOfStudy }}
              </p>
              <p class="sub-title" v-if="education.grade">
                CGPA: {{ education.grade }}
              </p>
              <p class="sub-title">{{ education.activities }}</p>
              <p class="sub-title" v-if="education.end_date">
                {{ education.start_date }} - {{ education.end_date }}
              </p>
              <p class="sub-title" v-else>
                {{ education.start_date }} - Present
              </p>
            </template>
          </div>
          <button
            class="main-btn main-btn__bg"
            v-if="edit_education"
            @click="showEducationModal"
          >
            Add new education
          </button>
        </div>
      </template>
      <!--**** education-section ends ****-->

      <!--**** Skills-section starts ****-->
      <!-- skills edit -->
      <div>
        <template v-if="skill_id">
          <div class="research-post--item">
            <h5 class="post-title">
              <div>Edit Skills</div>
              <div class="btn-edit text-danger" @click="reset()">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <!-- <div v-if="loadingSkills" class="loader">
              <h1 />
            </div> -->
            <Select
              filterable
              multiple
              placeholder="Select Skills"
              v-model="editData.skill_id"
              :remote-method="getSkills"
              :loading="isSkillLoading"
            >
              <Option v-for="(skill, i) in skills" :value="skill.id" :key="i">{{
                skill.name
              }}</Option>
            </Select>

            <div class="footer">
              <div></div>
              <div>
                <Button
                  class="main-btn main-btn__border"
                  @click="deleteSkills"
                  :disabled="deleting"
                  :loading="deleting"
                >
                  {{ deleting ? "Deleting..." : "Delete" }}</Button
                >
                <Button
                  class="main-btn main-btn__bg"
                  @click="updateSkills"
                  :disabled="loadingSkills"
                  :loading="loadingSkills"
                  ><i class="fa-solid fa-floppy-disk"></i>
                  {{ loadingSkills ? "Saving..." : "Save" }}</Button
                >
              </div>
            </div>
          </div>
        </template>

        <!-- skills -->
        <template v-else>
          <div class="research-post--item" v-if="profileInfo.user_skills != ''">
            <h5 class="post-title">
              <div>Skills</div>
              <div
                v-if="authUser.slug == this.$route.params.slug"
                class="btn-edit mx-2 float-end"
                @click="showEditSkills"
              >
                <i class="lni lni-pencil"></i>
              </div>
            </h5>
            <p>
              <span v-for="(skill, index) in profileInfo.user_skills"
                >{{ skill.name
                }}<span
                  class="dot"
                  v-if="profileInfo.user_skills.length - 1 > index"
                  >•</span
                ></span
              >
            </p>
          </div>
        </template>
      </div>
      <!--**** Skills-section ends ****-->

      <div>
        <div class="navbar-add--wrapper" v-bind:class="{ active: isSidebar }">
          <div class="navbar-add">
            <div class="navbar-add--head">
              <!-- <a href="#"><img src="assets/images/logo.png" alt="Logo" /></a> -->
              <h5 class="d-inline">Add Your Information</h5>
              <button type="button" v-on:click="hideSidebar()">
                <i class="lni lni-close"></i>
              </button>
            </div>
            <ul class="navbar-add--body">
              <li class="nav-item" @click="showAboutModal">
                <a class="nav-link">About</a>
              </li>

              <li class="nav-item" @click="showEducationModal">
                <a class="nav-link">Education</a>
              </li>
              <li class="nav-item" @click="showSkillsModal">
                <a class="nav-link">Skills</a>
              </li>
            </ul>

            <div class="navbar-add--head">
              <!-- <a href="#"><img src="assets/images/logo.png" alt="Logo" /></a> -->
              <h5 class="d-inline">Add Your Research</h5>
            </div>
            <ul class="navbar-add--body">
              <li class="nav-item" @click="showProjectModal">
                <a class="nav-link">Project</a>
              </li>
              <!-- <li class="nav-item" @click="showResearchModal()">
                <a class="nav-link">Thesis Paper</a>
              </li> -->
              <li
                class="nav-item"
                @click="showResearchModal('Conference Paper')"
              >
                <a class="nav-link">Conference Paper</a>
              </li>
              <li class="nav-item" @click="showResearchModal('Article')">
                <a class="nav-link">Article</a>
              </li>
              <li class="nav-item" @click="showResearchModal('Presentation')">
                <a class="nav-link">Presentation</a>
              </li>
              <li class="nav-item" @click="showResearchModal('Preprint')">
                <a class="nav-link">Preprint</a>
              </li>
              <li class="nav-item" @click="showResearchModal('Poster')">
                <a class="nav-link">Poster</a>
              </li>
              <li class="nav-item" @click="showResearchModal('Note')">
                <a class="nav-link">Note</a>
              </li>
            </ul>
          </div>
        </div>

        <!-- About modal -->
        <Modal v-model="aboutModal" :closable="false">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>About</div>
              <div class="btn-edit text-danger" @click="closeModal">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <textarea
              class="form-control"
              v-model="editData.about"
              rows="4"
              placeholder="Write About You..."
            ></textarea>
          </div>
          <div slot="footer">
            <div></div>
            <div>
              <Button
                class="main-btn main-btn__bg"
                @click="deleteAbout"
                :disabled="deleting"
                :loading="deleting"
                ><i class="fa-solid fa-floppy-disk"></i>
                {{ deleting ? "Deleting.." : "Delete" }}</Button
              >
              <Button
                class="main-btn main-btn__bg"
                @click="updateAbout"
                :disabled="isAdding"
                :loading="isAdding"
                ><i class="fa-solid fa-floppy-disk"></i>
                {{ isAdding ? "Saving.." : "Save" }}</Button
              >
            </div>
          </div>
        </Modal>

        <!-- Education modal -->
        <Modal v-model="educationModal" :closable="false">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>Add Education</div>
              <div class="btn-edit" @click="cancelEducationModal">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form label-position="top">
              <FormItem label="Institute *">
                <Input
                  v-model="educationData.institute"
                  placeholder="Ex: Leading University"
                ></Input>
                <span class="text-danger" v-if="errors.institute">{{
                  errors.institute[0]
                }}</span>
              </FormItem>
              <FormItem label="Degree">
                <Input
                  v-model="educationData.degree"
                  placeholder="Ex: Bachelor's"
                ></Input>
                <span class="text-danger" v-if="errors.degree">{{
                  errors.degree[0]
                }}</span>
              </FormItem>
              <FormItem label="Field of study">
                <Input
                  v-model="educationData.fieldOfStudy"
                  placeholder="Ex: Computer Science"
                ></Input>
                <span class="text-danger" v-if="errors.fieldOfStudy">{{
                  errors.fieldOfStudy[0]
                }}</span>
              </FormItem>

              <div class="row">
                <div class="col-6">
                  <FormItem label="Start Date">
                    <DatePicker
                      type="month"
                      v-model="educationData.start_date"
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
                      v-model="educationData.end_date"
                      placeholder="End Date (or expected)"
                      class="d-block"
                    ></DatePicker>
                    <span class="text-danger" v-if="errors.end_date">{{
                      errors.end_date[0]
                    }}</span>
                  </FormItem>
                </div>
              </div>
              <FormItem label="Grade">
                <Input
                  v-model="educationData.grade"
                  placeholder="Grade"
                ></Input>
                <span class="text-danger" v-if="errors.grade">{{
                  errors.grade[0]
                }}</span>
              </FormItem>
              <FormItem label="Description">
                <Input
                  v-model="educationData.activities"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 5 }"
                  placeholder="Write description..."
                ></Input>
                <span class="text-danger" v-if="errors.activities">{{
                  errors.activities[0]
                }}</span>
              </FormItem>
            </Form>
          </div>
          <div slot="footer">
            <button
              class="main-btn main-btn__border"
              @click="cancelEducationModal"
            >
              Cancel
            </button>
            <Button
              class="main-btn main-btn__bg"
              @click="saveEducation"
              :disabled="isAdding"
              :loading="isAdding"
            >
              <i class="fa-solid fa-floppy-disk"></i>
              {{ isAdding ? "Saving.." : "Save" }}
            </Button>
          </div>
        </Modal>

        <!-- Skills modal -->
        <Modal v-model="skillsModal" :closable="true" :mask-closable="false">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>Add Skills</div>
              <!-- <div class="btn-edit text-danger" @click="closeModal">
                <i class="fa-solid fa-xmark"></i>
              </div> -->
            </h5>
            <div class="mb-2">
              <Select
                filterable
                multiple
                placeholder="Select Skills"
                v-model="data.skill_id"
                :remote-method="getSkills"
                :loading="isSkillLoading"
              >
                <Option
                  v-for="(skill, index) in skills"
                  :value="skill.id"
                  :key="index"
                  >{{ skill.name }}</Option
                >
              </Select>
            </div>
          </div>
          <div slot="footer">
            <div>
              <button class="main-btn main-btn__border" @click="closeModal">
                Cancel
              </button>
              <Button
                class="main-btn main-btn__bg"
                @click="saveSkills"
                :disabled="isSkillAdding"
                :loading="isSkillAdding"
                >{{ isSkillAdding ? "Saving.." : "Save" }}</Button
              >
            </div>
          </div>
        </Modal>

        <!-- Research modal -->
        <Modal v-model="researchModal" :mask-closable="false" :closable="false">
          <div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div v-if="researchData.type == ''">Add Research</div>
              <div v-else>Add {{ researchData.type }}</div>

              <div class="btn-edit text-danger" @click="closeModal">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form label-position="top">
              <FormItem label="Type *">
                <Select v-model="researchData.type" placeholder="Select Type">
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
              <div v-if="researchData.type == 'Conference Paper'">
                <FormItem label="Conference *">
                  <Input
                    type="text"
                    v-model="researchData.conference"
                    placeholder="Conference"
                  />
                  <span class="text-danger" v-if="errors.conference">{{
                    errors.conference[0]
                  }}</span>
                </FormItem>
                <FormItem label="Publication Date">
                  <DatePicker
                    type="month"
                    v-model="researchData.publication_date"
                    placeholder="Publication Date"
                    class="d-block"
                  ></DatePicker>

                  <span class="text-danger" v-if="errors.publication_date">{{
                    errors.publication_date[0]
                  }}</span>
                </FormItem>
              </div>

              <FormItem label="Title *">
                <Input
                  type="text"
                  v-model="researchData.title"
                  placeholder="Title"
                />
                <span class="text-danger" v-if="errors.title">{{
                  errors.title[0]
                }}</span>
              </FormItem>

              <FormItem label="Abstract">
                <textarea
                  class="form-control form-outline"
                  v-model="researchData.abstract"
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
                  v-model="researchData.author_id"
                  :remote-method="getAuthors"
                  :loading="isSkillLoading"
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
                  v-model="researchData.affiliation"
                />
                <span class="text-danger" v-if="errors.affiliation">{{
                  errors.affiliation[0]
                }}</span>
              </FormItem>
              <FormItem label="URL">
                <Input
                  type="url"
                  v-model="researchData.url"
                  placeholder="URL"
                />
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
                  v-if="researchData.images"
                  v-for="(image, index) in researchData.images"
                >
                  <img :src="`${http + image}`" />
                  <div class="demo-upload-list-cover">
                    <Icon
                      type="ios-trash-outline"
                      @click="deleteImage(true, index)"
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
                      v-model="researchData.start_date"
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
                      v-model="researchData.end_date"
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
          </div>
          <div slot="footer">
            <div>
              <button class="main-btn main-btn__border" @click="closeModal">
                Cancel
              </button>
              <Button
                class="main-btn main-btn__bg"
                @click="saveResearch"
                :disabled="isAdding"
                :loading="isAdding"
                ><i class="fa-solid fa-floppy-disk"></i>
                {{ isAdding ? "Saving..." : "Save" }}</Button
              >
            </div>
          </div>
        </Modal>

        <!-- Peoject modal -->
        <Modal v-model="projectModal" :closable="false"
          ><div class="research-post--item" id="modal">
            <h5 class="post-title">
              <div>Add Project</div>
              <div class="btn-edit text-danger" @click="closeModal">
                <i class="fa-solid fa-xmark"></i>
              </div>
            </h5>
            <Form label-position="top">
              <FormItem label="Project Name *">
                <Input
                  v-model="researchData.title"
                  placeholder="Project Name"
                ></Input>
                <span class="text-danger" v-if="errors.title">{{
                  errors.title[0]
                }}</span>
              </FormItem>

              <FormItem label="Description">
                <Input
                  v-model="researchData.abstract"
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
                  v-model="researchData.author_id"
                  :remote-method="getAuthors"
                  :loading="isSkillLoading"
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
                  placeholder="Affiliation"
                  v-model="researchData.affiliation"
                />
                <span class="text-danger" v-if="errors.affiliation">{{
                  errors.affiliation[0]
                }}</span>
              </FormItem>
              <FormItem label="Project URL">
                <Input
                  type="url"
                  v-model="researchData.url"
                  placeholder="Project URL"
                />
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
                  v-if="researchData.images"
                  v-for="(image, index) in researchData.images"
                >
                  <img :src="`${http + image}`" />
                  <div class="demo-upload-list-cover">
                    <Icon
                      type="ios-trash-outline"
                      @click="deleteImage(true, index)"
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
                      v-model="researchData.start_date"
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
                      v-model="researchData.end_date"
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
          </div>
          <div slot="footer">
            <button class="main-btn main-btn__border" @click="closeModal">
              Cancel
            </button>
            <Button
              class="main-btn main-btn__bg"
              @click="saveResearch"
              :disabled="isAdding"
              :loading="isAdding"
              ><i class="fa-solid fa-floppy-disk"></i>
              {{ isAdding ? "Saving.." : "Save" }}</Button
            >
          </div>
        </Modal>

        <Modal v-model="deleteModal" width="360">
          <p slot="header" style="color: #7da2a9; text-align: center">
            <Icon type="close"></Icon>
            <span>Delete Education</span>
          </p>
          <div style="text-align: center">
            Are you sure you want to delete <b>{{ deleteValue.title }}</b> from
            your education?
          </div>
          <div slot="footer">
            <Button
              style="color: #7da2a9"
              size="large"
              long
              :loading="deleting"
              @click="educationRemove"
            >
              <span v-if="!deleting">Delete</span>
              <span v-else>Deleting...</span>
            </Button>
          </div>
        </Modal>
      </div>
    </div>
    <!--**** loader ****-->
    <div v-if="isLoading == true" class="mt-5">
      <!-- <button class="main-btn--skeleton w-100 mb-4"></button> -->
      <div class="research-post--skeleton--item mt-5">
        <div class="post-title-skeleton">
          <p></p>
        </div>
        <div class="post-sub-title-skeleton">
          <p></p>
        </div>
      </div>
      <div class="research-post--skeleton--item">
        <div class="post-title-skeleton">
          <p></p>
        </div>
        <div class="post-sub-title-skeleton">
          <p></p>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  middleware: "auth",

  data() {
    return {
      isSidebar: false,
      isLoading: true,
      isSkillLoading: false,
      isSkillAdding: false,
      isAdding: false,
      deleting: false,
      edit_education: false,
      loadingSkills: false,
      profileInfo: "",
      skills: [],
      users: [],
      educationInfo: "",
      user_slug: "",
      about_id: "",
      skill_id: "",
      token: "",
      data: {
        about: "",
        institute: "",
        skill_id: [],
        attachment: "",
      },
      editData: {
        about: "",
        skill_id: [],
        id: "",
      },
      educationData: {
        institute: "",
        degree: "",
        fieldOfStudy: "",
        start_date: "",
        end_date: "",
        grade: "",
        activities: "",
      },
      editEducationData: {
        id: null,
        index: -1,
        institute: "",
        degree: "",
        fieldOfStudy: "",
        start_date: "",
        end_date: "",
        grade: "",
        activities: "",
      },
      index: -1,
      attachmentName: "",
      isAttachmentLoading: false,
      researchData: {
        type: "",
        conference: "",
        publication_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        start_date: "",
        end_date: "",
      },
      deleteValue: {
        id: null,
        indexNumber: null,
        title: "",
      },
      aboutModal: false,
      educationModal: false,
      skillsModal: false,
      publicationsModal: false,
      projectsModal: false,
      researchModal: false,
      awardsModal: false,
      volunteerModal: false,
      projectModal: false,
      conferenceModal: false,
      deleteModal: false,
      errors: [],
      imageName: [],
      attachmentName: "",
      isEditingItem: false,
      isIconImageNew: false,
      iconImageName: "",
      http: this.$config.IMAGE_URL,
    };
  },

  methods: {
    showSidebar() {
      this.isSidebar = true;
    },
    hideSidebar() {
      this.isSidebar = false;
    },
    handleImageSuccess(res, file) {
      // this.iconImageName = `${res}`;
      this.imageName.push(`${res}`);

      res = `${res}`;

      console.log(res);
      // this.data.iconImage = res;
      this.researchData.images.push(res);
    },
    async deleteImage(isAdd, index) {
      let image;

      image = this.imageName[index];
      const res = await this.callApi("post", "/api/delete_image", {
        imageName: this.researchData.images[index],
      });
      // this.imageName.splice(index, 1);
      this.researchData.images.splice(index, 1);
      if (res.status != 200) {
        this.researchData.iconImage = image;
        this.swr();
      }
    },
    async deleteAttachment() {
      let attachment = this.attachmentName;
      // this.$refs.upload.clearFiles();
      this.attachmentName = "";
      this.researchData.attachment = "";

      const res = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      if (res.status != 200) {
        this.researchData.attachment = attachment;

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
      this.$refs.uploadAttachment.clearFiles();
      this.researchData.attachment = `${res}`;
      this.attachmentName = `${res}`;
      this.isAttachmentLoading = false;
    },
    async handleRemove(file, fileList) {
      let attachment = this.attachmentName;

      this.attachmentName = "";
      this.researchData.attachment = "";

      const res = await this.callApi("post", "/api/delete_attachment", {
        Name: attachment,
      });
      if (res.status != 200) {
        this.researchData.attachment = attachment;
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

    showAboutModal() {
      this.errors = [];
      let obj = {
        id: this.profileInfo.id,
        about: this.profileInfo.about,
      };
      this.editData = obj;
      this.aboutModal = true;
      this.isEditingItem = true;
      this.hideSidebar();
    },

    editAbout() {
      this.reset();
      this.editData.about = this.profileInfo.about;
      this.editData.id = this.profileInfo.id;
      this.about_id = this.profileInfo.id;
      // this.editData.skills = "";

      if (this.profileInfo) {
        this.$nextTick(() => {
          if (this.$refs["about" + this.profileInfo.about]) {
            this.$refs["about" + this.profileInfo.about].focus();
          }
        });
      }
    },
    async updateAbout() {
      // if (this.editData.about == "") return this.e("required");
      this.isAdding = true;
      const res = await this.callApi(
        "post",
        `/api/update_about`,
        this.editData
      );
      if (res.status === 200) {
        this.profileInfo.about = this.editData.about;
        this.closeModal();
        this.s("About has been updated successfully!");
        this.errors = [];
      } else {
        if (res.status == 422) {
          if (res.data.errors.about) {
            this.e(res.data.errors.about[0]);
          }
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
    },
    async deleteAbout() {
      if (this.profileInfo.id) {
        this.deleting = true;
        const res = await this.callApi("post", `/api/delete_about`);
        if (res.status === 200) {
          this.profileInfo.about = "";
          this.closeModal();
          this.s("About has been deleted successfully!");
        } else {
          this.swr();
        }
        this.deleting = false;
      }
    },

    //education
    showEducationModal() {
      this.errors = [];
      this.educationModal = true;
      this.educationData.institute = "";
      this.educationData.degree = "";
      this.educationData.fieldOfStudy = "";
      this.educationData.start_date = "";
      this.educationData.end_date = "";
      this.educationData.grade = "";
      this.educationData.activities = "";
      this.hideSidebar();
    },
    async saveEducation() {
      this.isAdding = true;
      const res = await this.callApi(
        "post",
        "/api/save_education",
        this.educationData
      );
      if (res.status === 201) {
        // this.educationInfo.unshift(res.data);
        this.s("Education has been added successfully!");
        this.educationModal = false;
        this.educationData.institute = "";
        this.educationData.degree = "";
        this.educationData.fieldOfStudy = "";
        this.educationData.start_date = "";
        this.educationData.end_date = "";
        this.educationData.grade = "";
        this.educationData.activities = "";
        this.reset();
      } else if (res.status == 422) {
        for (let i in res.data) {
          this.errors = res.data;
        }
      } else {
        this.swr();
      }
      this.isAdding = false;
    },
    showEditAllEducation() {
      this.errors = [];
      this.edit_education = true;
    },
    cancelEditEducation() {
      this.edit_education = false;
      this.editEducationData.id = "";
      this.editEducationData.institute = "";
      this.editEducationData.degree = "";
      this.editEducationData.fieldOfStudy = "";
      this.editEducationData.start_date = "";
      this.editEducationData.end_date = "";
      this.editEducationData.grade = "";
      this.editEducationData.activities = "";
      this.errors = [];
    },
    showEditSingleEducation(index) {
      if (this.educationInfo[index].id) {
        // this.editEducationData.index = index;
        // this.editEducationData.id = this.educationInfo[index].id;
        // this.editEducationData.email = this.educationInfo[index].email;
        // this.editEducationData.designation =
        //   this.educationInfo[index].designation;
        // this.editEducationData.department =
        //   this.educationInfo[index].department;
        let obj = {
          id: this.educationInfo[index].id,
          institute: this.educationInfo[index].institute,
          degree: this.educationInfo[index].degree,
          fieldOfStudy: this.educationInfo[index].fieldOfStudy,
          start_date: this.educationInfo[index].edit_start_date,
          end_date: this.educationInfo[index].edit_end_date,
          grade: this.educationInfo[index].grade,
          activities: this.educationInfo[index].activities,
        };
        this.editEducationData = obj;
        this.index = index;
        this.$nextTick(() => {
          if (this.$refs["institute" + this.educationInfo[index].id]) {
            this.$refs["institute" + this.educationInfo[index].id][0].focus();
          }
        });
      }
    },
    async updateEducation() {
      var startDate = this.editEducationData.start_date.toLocaleString(
        "en-us",
        { month: "short", year: "numeric" }
      );
      var endDate = this.editEducationData.end_date.toLocaleString("en-us", {
        month: "short",
        year: "numeric",
      });

      this.isAdding = true;
      const res = await this.callApi(
        "post",
        "/api/update_education",
        this.editEducationData
      );
      if (res.status === 200) {
        // this.reset();
        this.errors = [];
        this.educationInfo[this.index].id = this.editEducationData.id;
        this.educationInfo[this.index].institute =
          this.editEducationData.institute;
        this.educationInfo[this.index].degree = this.editEducationData.degree;
        this.educationInfo[this.index].fieldOfStudy =
          this.editEducationData.fieldOfStudy;
        this.educationInfo[this.index].start_date = startDate;
        this.educationInfo[this.index].end_date = endDate;
        this.educationInfo[this.index].grade = this.editEducationData.grade;
        this.educationInfo[this.index].activities =
          this.editEducationData.activities;
        this.cancelEditEducation();
        this.s("Education Updated!!");
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            // this.errors = res.data.errors;
            // this.e(res.data.errors[i][0]);
            this.e(res.data.errors[i][0]);
          }
        } else {
          this.swr();
        }
      }
      this.isAdding = true;
    },
    cancelEducationModal() {
      this.editEducationData.id = "";
      this.editEducationData.institute = "";
      this.editEducationData.degree = "";
      this.editEducationData.fieldOfStudy = "";
      this.editEducationData.startDate = "";
      this.editEducationData.endDate = "";
      this.editEducationData.grade = "";
      this.editEducationData.activities = "";
      this.errors = [];
      this.educationModal = false;
    },
    showEducationRemove(index) {
      this.deleteValue.title = this.educationInfo[index].institute;
      this.deleteValue.id = this.educationInfo[index].id;
      console.log(this.deleteValue.id);
      this.deleteValue.indexNumber = index;
      this.deleteModal = true;
    },
    async educationRemove(index) {
      let ob = {
        id: this.deleteValue.id,
      };
      this.deleting = true;
      const response = await this.callApi("post", "/api/delete_education", ob);
      if (response.status == 200) {
        this.educationInfo.splice(this.deleteValue.indexNumber, 1);
        this.s(this.deleteValue.title + " Deleted!!");
      } else {
        this.swr();
      }
      this.deleteModal = false;
      this.deleting = false;
    },
    showSkillsModal() {
      this.errors = [];
      this.data.skill_id = [];
      this.skillsModal = true;
      this.hideSidebar();
    },
    async saveSkills() {
      if (this.data.skill_id == []) return this.e("Skill Required");
      this.isSkillAdding = true;
      const res = await this.callApi("post", "/api/save_skills", this.data);
      if (res.status === 200) {
        this.data.skill_id = [];
        this.reset();
        this.s("Skills has been updated successfully!");
        this.skillsModal = false;
      } else {
        if (res.status == 422) {
          if (res.data.errors.skill_id) {
            this.e(res.data.errors.skill_id[0]);
          }
        } else {
          this.swr();
        }
      }
      this.isSkillAdding = false;
    },

    async showEditSkills() {
      this.reset();
      // this.data.skill_id = profileInfo.user_skills;
      this.editData.id = this.profileInfo.id;
      this.skill_id = this.profileInfo.id;
      this.editData.about = "";
      this.user_slug = this.$route.params.slug;
      this.loadingSkills = true;
      // const response = await this.callApi("get", `/api/get_skills`);
      // if (response.status == 200) {
      //   this.skills = profileInfo.user_skills;
      // }
      this.skills = this.profileInfo.user_skills;

      for (let t of this.profileInfo.user_skills) {
        this.editData.skill_id.push(parseInt(t.id));
      }
      this.loadingSkills = false;
    },
    async updateSkills() {
      if (this.editData.skill_id == []) return this.e("required");
      this.loadingSkills = true;

      const res = await this.callApi(
        "post",
        `/api/update_skills`,
        this.editData
      );
      if (res.status === 200) {
        // for (let t of this.editData.skill_id) {
        //   this.profileInfo.user_skills.push(parseInt(t.id));
        // }
        // this.profileInfo.skills = this.editData.skills;
        this.reset();
        this.s("Skills has been updated successfully!");
      } else {
        if (res.status == 422) {
          if (res.data.errors.about) {
            this.e(res.data.errors.about[0]);
          }
        } else {
          this.swr();
        }
      }
      this.loadingSkills = false;
    },
    async deleteSkills() {
      this.deleting = true;

      const res = await this.callApi("post", `/api/delete_skills`);
      if (res.status === 200) {
        this.s(res.data.msg);
        this.reset();
      } else {
        this.swr();
      }
      this.deleting = false;
    },
    showProjectModal() {
      this.errors = [];
      this.researchData = {
        type: "",
        conference: "",
        publication_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        start_date: "",
        end_date: "",
      };
      this.researchData.type = "Project";
      this.researchData.images = [];
      this.projectModal = true;
      this.hideSidebar();
    },

    async showResearchModal(type) {
      this.errors = [];
      this.researchData = {
        type: "",
        conference: "",
        publication_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        start_date: "",
        end_date: "",
      };
      this.researchData.type = type;
      this.getAuthors(this.authUser.name);
      this.researchData.author_id.push(this.authUser.id);
      this.researchModal = true;
      this.hideSidebar();
    },
    async saveResearch() {
      // if (this.data.project_name.trim() == "")
      //     return this.e("Project Name is required");
      // if (this.data.project_type.trim() == "")
      //     return this.e("Project type is required");
      // if (this.data.start_date.trim() == "")
      //     return this.e("Start date is required");

      const res = await this.callApi(
        "post",
        "/api/save_post",
        this.researchData
      );
      this.isAdding = true;
      if (res.status === 200) {
        this.s("Updated");

        this.closeModal();
      } else {
        if (res.status == 422) {
          for (let i in res.data.errors) {
            this.errors = res.data.errors;
          }
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
    },
    async getSkills(query) {
      this.isSkillLoading = true;
      const response = await this.callApi(
        "get",
        `/api/search_skills?keyword=${query}`
      );
      if (response.status == 200) {
        this.skills = response.data;
      }
      this.isSkillLoading = false;
    },
    async getAuthors(query) {
      console.log(query);
      this.isSkillLoading = true;
      const response = await this.callApi(
        "get",
        `/api/search?keyword=${query}`
      );
      if (response.status == 200) {
        this.users = response.data;
      }
      this.isSkillLoading = false;
    },

    closeModal() {
      this.aboutModal = false;
      this.skillsModal = false;
      this.projectModal = false;
      this.researchModal = false;

      // this.researchData.type = "";
      // this.researchData.title = "";
      // this.researchData.author_id = [];
      // this.researchData.attachment = "";
      // this.researchData.abstract = "";
      // this.researchData.start_date = "";
      // this.researchData.end_date = "";
      // this.researchData.url = "";
      this.attachmentName = "";
      this.researchData = {
        type: "",
        conference: "",
        publication_date: "",
        title: "",
        author_id: [],
        attachment: "",
        abstract: "",
        url: "",
        images: [],
        start_date: "",
        end_date: "",
      };
      //
      this.user_slug = "";
      this.editData.about = "";
      this.about_id = "";
      this.editData.skill_id = [];
      this.skill_id = "";
      this.data.skill_id = [];
    },

    async reset() {
      this.user_slug = "";
      this.editData.about = "";
      this.about_id = "";
      this.editData.skill_id = [];
      this.skill_id = "";
      this.aboutModal = false;
      this.skillsModal = false;
      this.projectModal = false;
      this.researchModal = false;

      this.user_slug = this.$route.params.slug;
      const res = await this.callApi(
        "get",
        `/api/get_profile_info/${this.user_slug}`
      );

      if (res.status == 200) {
        this.profileInfo = res.data.user;
        this.educationInfo = res.data.education;
      } else {
        this.swr();
      }
      this.isLoading = false;
    },
  },
  watch: {
    "$route.params"(oldValue, newValue) {
      if (oldValue != newValue) {
        console.log("route is changing!");
        this.reset();
      }
    },
  },
  async created() {
    // this.token = window.Laravel.csrfToken;

    this.user_slug = this.$route.params.slug;
    if (this.authUser) {
      const res = await this.callApi(
        "get",
        `/api/get_profile_info/${this.user_slug}`
      );

      if (res.status == 200) {
        this.profileInfo = res.data.user;
        this.educationInfo = res.data.education;
      } else {
        this.swr();
      }
    } else {
      window.location = "/";
      // this.$router.push("/");
    }

    this.isLoading = false;
  },
};
</script>

<style scoped>
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
