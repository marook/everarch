/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <gtk/gtk.h>

static void activate_main_widget(GApplication * app);

int main(int argc, char *argv[]){
    GtkApplication *app =
        gtk_application_new("de.ma300k.evr.evr-attr-ui", G_APPLICATION_NON_UNIQUE | G_APPLICATION_HANDLES_OPEN);

    g_signal_connect(G_APPLICATION(app), "activate", G_CALLBACK(activate_main_widget), NULL);

    int ret = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return ret;
}

static void activate_main_widget(GApplication *app){
    GtkWidget *main_win = gtk_application_window_new(GTK_APPLICATION(app));
    // TODO
    gtk_widget_show_all(main_win);
}
