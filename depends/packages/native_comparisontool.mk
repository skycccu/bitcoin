package=native_comparisontool
$(package)_version=5d7311d
$(package)_download_path=https://github.com/TheBlueMatt/test-scripts/raw/efa8458abce0eb9fc78bfa1254e3ae971eb599ff
$(package)_file_name=pull-tests-$($(package)_version).jar
$(package)_sha256_hash=c2e6929def846fff90750a9a5e8d4f2366ac9b664e2cc791ecc13b9736338f80
$(package)_install_dirname=BitcoindComparisonTool_jar
$(package)_install_filename=BitcoindComparisonTool.jar

define $(package)_extract_cmds
endef

define $(package)_configure_cmds
endef

define $(package)_build_cmds
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/share/$($(package)_install_dirname) && \
  mv $(SOURCES_PATH)/$($(package)_file_name) $($(package)_staging_prefix_dir)/share/$($(package)_install_dirname)/$($(package)_install_filename)
endef
